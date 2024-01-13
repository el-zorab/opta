#include <Ethernet.h>
#include <EthernetUdp.h>
#include <mbed_mktime.h>
#include <SPI.h>
#include <time.h>
#include "aes.h"
#include "sha256.h"
#include "hmac_sha256.h"

// hardware
const int RELAYS[] = { D0, D1, D2, D3 };
const int LEDS[]   = { LED_D0, LED_D1, LED_D2, LED_D3 };

// constants
const unsigned int  API_MAX_INT_LEN          = 16;
const unsigned int  AES_MAX_LEN              = 256;
const unsigned int  IV_LEN                   = 16;
const unsigned int  HMAC_MAX_INPUT_SIZE      = 2 * (AES_MAX_LEN + IV_LEN);
const unsigned int  HMAC_KEY_SIZE            = 64;
const unsigned int  HTTP_MAX_REQ_LEN         = 512;
const unsigned int  PAYLOAD_MAX_SIZE         = AES_MAX_LEN + IV_LEN + SHA256_HASH_SIZE;
const unsigned long TIMESTAMP_MAX_DIFFERENCE = 5;
const unsigned int  TOKEN_MAX_LENGTH         = 32;

const unsigned int  NTP_PACKET_SIZE   = 48;
const unsigned long NTP_MAX_WAIT_TIME = 5000;
const unsigned int  RTC_SYNC_INTERVAL = 30 * 60 * 1000UL; // 30 minutes
const unsigned int  UDP_PORT          = 8888;

const unsigned long RELAY_UNLATCH_TIME    = 1500;
const unsigned long BUTTON_DEBOUNCE_DELAY = 150;

struct AES_ctx aes_ctx;

uint8_t AES_KEY[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

uint8_t HMAC_KEY[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// which Opta is the code running on? (0, 1 or 2)
const int OPTA_NUMBER = 2;

uint8_t ips[3][4] = {
  { 192, 168, 11, 177 },
  { 192, 168, 11, 178 },
  { 192, 168, 11, 179 }
};

// Ethernet local IP
IPAddress ip(ips[OPTA_NUMBER][0], ips[OPTA_NUMBER][1], ips[OPTA_NUMBER][2], ips[OPTA_NUMBER][3]);

// HTTP client for making requests to API server
EthernetClient client;

// HTTP server for receiving API requests
EthernetServer server(8088);

// Header name, used for receiving and sending API requests
const char* PAYLOAD_HEADER_NAME = "Payload";

// NTP Server used for calibrating the RTC
const char NTP_SERVER[] = "time.nist.gov";

// Last time the RTC was synced with the NTP server
unsigned long last_rtc_sync;

// UDP
EthernetUDP Udp;
uint8_t udp_buffer[NTP_PACKET_SIZE];

// 3 buttons (A0, A1 and BTN_USER)
volatile bool button_pressed[]       = {false, false, false};
unsigned long button_last_debounce[] = {0, 0, 0};

uint8_t relay_states[]         = {0, 0, 0, 0};
uint8_t relay_latched_states[] = {0, 0, 0, 0};
bool    relays_latched         = false;

// API
const char* API_SERVER_IP   = "192.168.11.214";
const char* API_SERVER_URL  = "/api";
int         API_SERVER_PORT = 80;

int  api_receive_counter = 0;
int  api_send_counter    = 0;

bool api_button_interrupts_enabled = true;

enum APIReceivedType {
  CHANGE_RELAY_STATES = 0,
  CHANGE_BUTTON_INTERRUPTS_STATE = 1
};

enum APISentType {
  RELAY_STATES_CHANGED = 0,
  ENABLE_BUTTON_INTERRUPTS = 1
};

void setup() {
  Serial.begin(9600);
  
  pinMode(LEDR, OUTPUT);

  attach_button_interrupts();
  attachInterrupt(digitalPinToInterrupt(BTN_USER), master_button_isr, RISING);

  Ethernet.begin(ip);

  if (Ethernet.linkStatus() == LinkON) {
    server.begin();
    Udp.begin(UDP_PORT);
    rtc_sync();
    srand((unsigned int) time(NULL));
  }
}
 
void loop() {
  if (Ethernet.linkStatus() == LinkON) {
    Ethernet.maintain();
    http_server_loop();
    rtc_check_for_sync();
  }
  buttons_press_listener();
  master_button_press_listener();
  master_button_check_for_unlatch();
}

// API
void api_receive(uint8_t data[], int data_len) {
  char data_str[AES_MAX_LEN];
  for (int i = 0; i < data_len; i++) {
    data_str[i] = (char) data[i];
  }
  data_str[data_len] = 0;

  // data is a string of "tokens", ordered in a specific order and separated by a semicolon
  char token[TOKEN_MAX_LENGTH];
  int  token_len = 0;
  int  token_counter = 0;

  enum APIReceivedType type;

  for (int i = 0; i < data_len; i++) {
    if (data[i] == ';') {
      // add terminating null byte
      token[token_len] = 0;

      // token handling
      switch (token_counter) {
        case 0: { // API request counter
          int received_counter_in_data = strtol(token, NULL, 10);
          if (received_counter_in_data < api_receive_counter) {
            // Serial.println("Payload discarded (API counter check failed)");
            return;
          }

          api_receive_counter++;
        } break;

        case 1: { // received timestamp
          long current_timestamp = rtc_get_unix_timestamp();
          long received_timestamp = strtol(token, NULL, 10);
          if (abs(current_timestamp - received_timestamp) > TIMESTAMP_MAX_DIFFERENCE) {
            // Serial.println("Payload discarded (Timestamp check failed)");
            return;
          };
        } break;

        case 2: { // API request type
          type = (APIReceivedType) (token[0] - '0');
        } break;

        case 3: { // extra token (depends on API request type)
          if (type == CHANGE_RELAY_STATES) { // the extra token is the relays states
            for (int i = 0; i < 4; i++) {
              token[i] = token[i] - '0';
            }

            set_relay_states((uint8_t *) token);
          } else if (type == CHANGE_BUTTON_INTERRUPTS_STATE) { // the extra token is the new button interrupts state
            api_button_interrupts_enabled = token[0] - '0';

            if (api_button_interrupts_enabled == 0) {
              detach_button_interrupts();
            } else if (api_button_interrupts_enabled == 1) {
              attach_button_interrupts();
            }
          }
        } break;
      }

      token_len = 0;
      token_counter++;
    } else {
      token[token_len++] = data[i];
    }
  }
}

void api_send(enum APISentType type) {
  uint8_t payload[PAYLOAD_MAX_SIZE];
  char    payload_hex_str[2 * AES_MAX_LEN + 1];

  uint8_t iv[IV_LEN];
  uint8_t hmac[SHA256_HASH_SIZE];

  uint8_t api_data[AES_MAX_LEN];
  int     api_data_len = 0;

  char integer_as_str[API_MAX_INT_LEN];

  // create API data

  // convert `api_send_cnt` from integer to a char array and add it to the payload
  int api_cnt_str_len = sprintf(integer_as_str, "%d", api_send_counter);

  for (int i = 0; i < api_cnt_str_len; i++) {
    api_data[api_data_len++] = integer_as_str[i];
  }
  api_data[api_data_len++] = ';';

  // convert unix timestamp from integer to a char array and add it to the payload
  int timestamp_str_len = sprintf(integer_as_str, "%lu", rtc_get_unix_timestamp());

  for (int i = 0; i < timestamp_str_len; i++) {
    api_data[api_data_len++] = integer_as_str[i];
  }
  api_data[api_data_len++] = ';';

  // tell the server which Opta was the request sent from
  api_data[api_data_len++] = OPTA_NUMBER + '0';
  api_data[api_data_len++] = ';';

  // API request type
  api_data[api_data_len++] = type + '0';
  api_data[api_data_len++] = ';';

  if (type == RELAY_STATES_CHANGED) {
    // add relay states to the payload
    for (int i = 0; i < 4; i++) {
      api_data[api_data_len++] = relay_states[i] + '0';
    }
    api_data[api_data_len++] = ';';
  }

  // payload is (iv + aes(data) + hmac(iv + aes))

  // randomize IV and add it to payload
  randomize_bytes(iv, IV_LEN);
  for (int i = 0; i < IV_LEN; i++) {
    payload[i] = iv[i];
  }

  int iv_start     = 0;
  int iv_end       = IV_LEN;
  int cipher_start = iv_end;
  int cipher_len;

  // create cipher and add it to the payload, after the IV
  aes_encrypt(api_data, api_data_len, iv, payload + cipher_start, &cipher_len);

  int cipher_end = cipher_start + cipher_len;
  int hmac_start = cipher_end;
  int hmac_end   = hmac_start + SHA256_HASH_SIZE;

  // use the `payload_hex_str` char array as the hmac input array
  // don't forget the resulting array is of size (2 * cipher_end)
  // since every byte is written as two char's
  bytes_to_hex_str(payload, cipher_end, payload_hex_str);

  // compute hmac and add it to the `payload_hex_str` char array, after the cipher
  hmac_sha256(HMAC_KEY,             HMAC_KEY_SIZE,
              payload_hex_str,      2 * cipher_end,
              payload + hmac_start, SHA256_HASH_SIZE);

  // we already have the IV and the cipher in the `payload_hex_str` array
  // so we only need to add the computed hmac
  // and then we can send the payload string
  bytes_to_hex_str(payload + hmac_start, SHA256_HASH_SIZE, payload_hex_str + 2 * hmac_start);

  // send the payload
  if (client.connect(API_SERVER_IP, API_SERVER_PORT)) {
    client.print("GET ");
    client.print(API_SERVER_URL);
    client.println(" HTTP/1.0");
    client.println("Connection: close");
    client.print(PAYLOAD_HEADER_NAME);
    client.print(": ");
    client.println(payload_hex_str);
    client.println();

    client.flush();

    api_send_counter++;
  }
  client.stop();
}

// Hardware button interrupts
void buttons_press_listener() {
  for (int i = 0; i < 2; i++) {
    if (!button_pressed[i]) continue;
    button_pressed[i] = false;

    if (millis() - button_last_debounce[i] < BUTTON_DEBOUNCE_DELAY) continue;
    button_last_debounce[i] = millis();

    uint8_t a, b;
    a = relay_states[2 * i];
    b = relay_states[2 * i + 1];

    if (a == 0 && b == 0) {
      a = 1;
      b = 0;
    } else if (a == 1 && b == 0) {
      a = 1;
      b = 1;
    } else if (a == 1 && b == 1) {
      a = 0;
      b = 1;
    } else if (a == 0 && b == 1) {
      a = 0;
      b = 0;
    }

    set_relay_state(2 * i,     a);
    set_relay_state(2 * i + 1, b);

    if (Ethernet.linkStatus() == LinkON) api_send(RELAY_STATES_CHANGED);
  }
}

void master_button_press_listener() {
  if (!button_pressed[2]) return;
  button_pressed[2] = false;

  if (millis() - button_last_debounce[2] < BUTTON_DEBOUNCE_DELAY) return;
  button_last_debounce[2] = millis();

  if (!api_button_interrupts_enabled) {
    attach_button_interrupts();
    api_button_interrupts_enabled = true;
    if (Ethernet.linkStatus() == LinkON) api_send(ENABLE_BUTTON_INTERRUPTS);
    return;
  }

  if (!relays_latched) {
    relays_latched = true;
    detach_button_interrupts();

    for (int i = 0; i < 4; i++) {
      relay_latched_states[i] = relay_states[i];
    }
  }

  uint8_t counter = relay_latched_states[0] << 3 | relay_latched_states[1] << 2 | relay_latched_states[2] << 1 | relay_latched_states[3];
  counter = (counter + 1) & 15;

  relay_latched_states[0] = (counter >> 3) & 1;
  relay_latched_states[1] = (counter >> 2) & 1;
  relay_latched_states[2] = (counter >> 1) & 1;
  relay_latched_states[3] = counter & 1;

  for (int i = 0; i < 4; i++) {
    digitalWrite(LEDS[i], relay_latched_states[i]);
  }
}

void master_button_check_for_unlatch() {
  if (relays_latched && millis() - button_last_debounce[2] > RELAY_UNLATCH_TIME) {
    set_relay_states(relay_latched_states);
    relays_latched = false;

    attach_button_interrupts();

    if (Ethernet.linkStatus() == LinkON) api_send(RELAY_STATES_CHANGED);
  }
}

void attach_button_interrupts() {
  attachInterrupt(digitalPinToInterrupt(A0), button0_isr, RISING);
  attachInterrupt(digitalPinToInterrupt(A1), button1_isr, RISING);
  digitalWrite(LEDR, LOW);
}

void detach_button_interrupts() {
  detachInterrupt(digitalPinToInterrupt(A0));
  detachInterrupt(digitalPinToInterrupt(A1));
  digitalWrite(LEDR, HIGH);
}

// Wrapper functions to set relay state(s)
void set_relay_state(uint8_t relay, uint8_t state) {
  relay_states[relay] = state;
  digitalWrite(LEDS[relay],   state);
  digitalWrite(RELAYS[relay], state);
}

void set_relay_states(uint8_t r_states[]) {
  for (int i = 0; i < 4; i++) {
    relay_states[i] = r_states[i];
    digitalWrite(LEDS[i],   r_states[i]);
    digitalWrite(RELAYS[i], r_states[i]);
  }
}

// ISRs
void button0_isr() {
  button_pressed[0] = true;
}

void button1_isr() {
  button_pressed[1] = true;
}

void master_button_isr() {
  button_pressed[2] = true;
}

// API payload validation
void api_receive_validation(char *payload_hex_str) {
  int payload_str_len = 0;
  while (payload_hex_str[payload_str_len] != 0 && payload_str_len <= 2 * PAYLOAD_MAX_SIZE) {
    payload_str_len++;
  }
  payload_hex_str[payload_str_len] = 0;

  if (payload_str_len > 2 * PAYLOAD_MAX_SIZE) {
    // Serial.println("Payload discarded (payload length too big)");
    return;
  }

  // AES encrypts messages in blocks of 16 bytes (that would be 32 char's)
  // subtracting [(IV + HMAC) size in bytes] * 2 (each byte takes two char's)
  // we should get a multiple of 32
  int cipher_str_len = payload_str_len - 2 * (IV_LEN + SHA256_HASH_SIZE);
  if (cipher_str_len & 31 != 0) {
    // Serial.println("Payload discarded (invalid payload length)");
    return;
  }
  
  // remember, each byte takes two char's
  if (cipher_str_len > 2 * AES_MAX_LEN) {
    // Serial.println("Payload discarded (AES exceeds maximum length)");
    return;
  }

  uint8_t payload[PAYLOAD_MAX_SIZE];
  int     payload_len;

  uint8_t data[AES_MAX_LEN];
  int     data_len;

  uint8_t hmac[SHA256_HASH_SIZE];

  // payload is [iv + aes(data) + hmac(aes + iv)]
  hex_str_to_bytes(payload_hex_str, payload_str_len, payload);
  payload_len = payload_str_len / 2;

  int iv_start     = 0;
  int iv_end       = IV_LEN;
  int cipher_start = iv_end;
  int cipher_end   = payload_len - SHA256_HASH_SIZE;
  int hmac_start   = cipher_end;
  int hmac_end     = payload_len;

  // hmac(iv + aes)
  hmac_sha256(HMAC_KEY, HMAC_KEY_SIZE, payload_hex_str + 2 * iv_start, 2 * (cipher_end - iv_start), hmac, SHA256_HASH_SIZE);

  // verify computed HMAC and received HMAC are equal
  for (int i = 0; i < SHA256_HASH_SIZE; i++) {
    if (hmac[i] != payload[hmac_start + i]) {
      // Serial.println("Payload discarded (HMAC validation failed)");
      return;
    }
  }

  aes_decrypt(payload + cipher_start, cipher_end - cipher_start, payload + iv_start, data, &data_len);

  api_receive(data, data_len);
}

// HTTP server
void http_server_loop() {
  EthernetClient client = server.available();

  if (!client) return;

  char req_str[HTTP_MAX_REQ_LEN];
  int  req_len = 0;
  bool is_current_line_blank = true;

  while (client.connected()) {
    if (client.available()) {
      char ch = client.read();
      req_str[req_len++] = ch;

      if (req_len == HTTP_MAX_REQ_LEN) return;

      if (is_current_line_blank && ch == '\n') {
        req_str[req_len] = 0;

        char *payload_hdr     = strstr(req_str, PAYLOAD_HEADER_NAME);
        char *payload_hdr_end = strchr(payload_hdr, '\r');

        if (payload_hdr_end != NULL) {
          *payload_hdr_end = 0;
        }

        if (payload_hdr[7] == ':' && payload_hdr[8] == ' ') {
          char *payload = payload_hdr + 9;
          api_receive_validation(payload);
        } else {
          client.println("HTTP/1.1 401 Unauthorized");
          client.println("Content-Type: text/html");
          client.println("Connection: close");
          break;
        }

        client.println("HTTP/1.1 204 No Content");
        client.println("Content-Type: text/html");
        client.println("Connection: close");
        break;
      }

      if (ch == '\n') {
        is_current_line_blank = true;
      } else if (ch != '\r') {
        is_current_line_blank = false;
      }
    }
  }

  delay(1);
  client.stop();
}

// Utility functions
void bytes_to_hex_str(uint8_t in[], int in_len, char out[]) {
  for (int i = 0; i < in_len; i++) {
    uint8_t high_nibble = in[i] >> 4;
    uint8_t low_nibble = in[i] & 15;

    if (high_nibble < 10) {
      high_nibble = high_nibble + '0';
    } else {
      high_nibble = high_nibble + 'a' - 10;
    }

    if (low_nibble < 10) {
      low_nibble = low_nibble + '0';
    } else {
      low_nibble = low_nibble + 'a' - 10;
    }

    out[2 * i] = high_nibble;
    out[2 * i + 1] = low_nibble;
  }

  out[2 * in_len] = 0;
}

void hex_str_to_bytes(char in[], int in_len, uint8_t out[]) {
  for (int i = 0; i < in_len; i++) {
    uint8_t high_nibble = in[2 * i];
    uint8_t low_nibble  = in[2 * i + 1];
    
    if (high_nibble <= '9') {
      high_nibble = high_nibble - '0';
    } else {
      high_nibble = high_nibble - 'a' + 10;
    }

    if (low_nibble <= '9') {
      low_nibble = low_nibble - '0';
    } else {
      low_nibble = low_nibble - 'a' + 10;
    }

    out[i] = (high_nibble << 4) | low_nibble;
  }
}

void randomize_bytes(uint8_t in[], int in_len) {
  for (int i = 0; i < in_len; i++) {
    in[i] = rand();
  }
}

// AES wrapper functions
void aes_encrypt(uint8_t in[], int in_len, uint8_t iv[], uint8_t out[], int *out_len) {
  for (int i = 0; i < in_len; i++) {
    out[i] = in[i];
  }

  *out_len = (in_len / 16 + 1) * 16;

  int bytes_to_add = *out_len - in_len;
  for (int i = in_len; i < *out_len; i++) {
    out[i] = bytes_to_add; // add alignment bytes (PKCS7 standard)
  }

  AES_init_ctx_iv(&aes_ctx, AES_KEY, iv); 
  AES_CBC_encrypt_buffer(&aes_ctx, out, *out_len);

  out[*out_len] = 0;
}

void aes_decrypt(uint8_t in[], int in_len, uint8_t iv[], uint8_t out[], int *out_len) {
  for (int i = 0; i < in_len; i++) {
    out[i] = in[i];
  }

  *out_len = in_len;

  AES_init_ctx_iv(&aes_ctx, AES_KEY, iv);
  AES_CBC_decrypt_buffer(&aes_ctx, out, *out_len);

  *out_len = in_len - 16;
  while (out[*out_len] > 16) { 
    (*out_len)++; // remove alignment bytes (PKCS7 standard)
  }

  out[*out_len] = 0;
}

// NTP (https://github.com/arduino-libraries/Ethernet/blob/master/examples/UdpNtpClient/UdpNtpClient.ino)
void ntp_send_packet(const char *address) {
  memset(udp_buffer, 0, NTP_PACKET_SIZE);

  udp_buffer[0] = 0b11100011;
  udp_buffer[1] = 0;
  udp_buffer[2] = 6; 
  udp_buffer[3] = 0xEC;

  udp_buffer[12]  = 49;
  udp_buffer[13]  = 0x4E;
  udp_buffer[14]  = 49;
  udp_buffer[15]  = 52;

  Udp.beginPacket(address, 123);
  Udp.write(udp_buffer, NTP_PACKET_SIZE);
  Udp.endPacket();
}

unsigned long ntp_get_unix_timestamp() {
  ntp_send_packet(NTP_SERVER);
  
  unsigned long millis_at_request = millis();

  while (1) {
    if (Udp.parsePacket()) {
      Udp.read(udp_buffer, NTP_PACKET_SIZE);

      unsigned long high_word = word(udp_buffer[40], udp_buffer[41]);
      unsigned long low_word = word(udp_buffer[42], udp_buffer[43]);

      const unsigned long SEVENTY_YEARS = 2208988800UL;

      return (high_word << 16 | low_word) - SEVENTY_YEARS;
    }

    if (millis() - millis_at_request > NTP_MAX_WAIT_TIME) return -1;
  }
}

// RTC
void rtc_sync() {
  unsigned long ntp_unix_timestamp = ntp_get_unix_timestamp();
  if (ntp_unix_timestamp != -1) {
    set_time(ntp_unix_timestamp);
    last_rtc_sync = millis();
  }
}

void rtc_check_for_sync() {
  if (millis() - last_rtc_sync > RTC_SYNC_INTERVAL) {
    rtc_sync();
  }
}

time_t rtc_get_unix_timestamp() {
  tm t;
  time_t seconds;
  _rtc_localtime(time(NULL), &t, RTC_FULL_LEAP_YEAR_SUPPORT);
  _rtc_maketime(&t, &seconds, RTC_FULL_LEAP_YEAR_SUPPORT);
  return seconds;
}
