'use strict';

const crypto     = require('crypto');
const exec       = require('child_process').exec;

const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');

const fs         = require('fs');
const path       = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// API request types
const APIReceivedType = {
  RELAY_STATES_CHANGED: 0,
  ENABLE_BUTTON_INTERRUPTS: 1
};

const APISentType = {
  CHANGE_RELAY_STATES: 0,
  CHANGE_BUTTON_INTERRUPTS_STATE: 1
};

const APIReceivedToken = {
  REQUEST_COUNTER: 0,
  TIMESTAMP: 1,
  OPTA_NUMBER: 2,
  REQUEST_TYPE: 3,
  EXTRA_PARAM: 4
}

// cipher, hmac and iv size in bytes
const AES_MAX_SIZE = 256;
const HMAC_SIZE    = 32;
const IV_SIZE      = 16;

// max timestamp difference (in seconds)
const TIMESTAMP_MAX_DIFFERENCE = 5;

// counter for received and sent API requests
const api_receive_counter = [0, 0, 0];
const api_send_counter    = [0, 0, 0];

const OPTA_COUNT = 3;
const RELAYS_PER_OPTA = 4;

const opta_ips  = ['192.168.0.177', '192.168.0.178', '192.168.0.179'];
const opta_port = 8088;

const AES_KEY = Buffer.from(fs.readFileSync(path.join(__dirname, 'aes_key'), {encoding: 'utf-8'}), 'hex');
const HMAC_KEY = Buffer.from(fs.readFileSync(path.join(__dirname, 'hmac_key'), {encoding: 'utf-8'}), 'hex');

// relay states
let relays = new Array(OPTA_COUNT * RELAYS_PER_OPTA).fill(0);

// interrupts disabled/enabled ?
let hardware_interrupts_enabled = true;

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// route for opta's
app.get('/api', (req, res) => {
  let payload = req.headers['payload'];
  if (payload != null) api_receive(payload);
  else res.sendStatus(401); // Unauthorized
});

io.on('connection', (socket) => {
  console.log('a user connected');

  // set the relay buttons states on webpage load
  socket.emit('update_relay_buttons', relays);

  // set the toggle interrupts button state
  socket.emit('update_interrupts_button', hardware_interrupts_enabled);

  // when a relay state is changed from the webpage
  socket.on('relay_button_change', data => {
    // set new relay state
    relays[data.relay] = data.state ? 1 : 0;

    // update relay buttons for other clients
    socket.broadcast.emit('update_relay_buttons', relays);

    // which opta should we send the update to
    let opta = Math.floor(data.relay / RELAYS_PER_OPTA);

    // create api_data and send it
    let api_send_str = `${APISentType.CHANGE_RELAY_STATES};`;
    for (let i = 0; i < RELAYS_PER_OPTA; i++) {
      api_send_str += relays[opta * RELAYS_PER_OPTA + i];
    }
    api_send_str += ';';
    api_send(api_send_str, opta);
  });

  // when the interrupts are enabled/disabled from the webpage
  socket.on('interrupts_button_change', is_enabled => {
    hardware_interrupts_enabled = is_enabled;

    let api_send_str = `${APISentType.CHANGE_BUTTON_INTERRUPTS_STATE};${hardware_interrupts_enabled == true ? '1' : '0'};`;

    // change the interrupts state on all Opta's
    for (let i = 0; i < OPTA_COUNT; i++) {
      api_send(api_send_str, i);
    }
  });
});

server.listen(80, () => {
  console.log('listening on *:80');
});

function api_receive(payload) {
  let payload_len = payload.length;

  if ((payload_len - 2 * (IV_SIZE + HMAC_SIZE)) % 32 != 0) {
    console.log(`Payload discarded (invalid payload length)`);
    return;
  }

  if (payload_len > 2 * (IV_SIZE + AES_MAX_SIZE + HMAC_SIZE)) {
    console.log(`Payload discarded (AES exceeds maximum length)`);
    return;
  }

  let iv_start     = 0;
  let iv_end       = 2 * IV_SIZE;
  let cipher_start = iv_end;
  let cipher_end   = payload_len - 2 * HMAC_SIZE;
  let hmac_start   = cipher_end;
  let hmac_end     = payload_len;

  let iv = payload.substring(iv_start, iv_end);
  let cipher = payload.substring(cipher_start, cipher_end);
  let payload_hmac = payload.substring(hmac_start, hmac_end);

  let hmac = create_hmac(iv + cipher);
  if (hmac != payload_hmac) {
    console.log(`Payload discarded (HMAC validation failed)`);
    return;
  }

  let data = aes_decrypt_iv(cipher, Buffer.from(iv, 'hex'));
  let tokens = data.split(';'); // separate the data in "tokens"

  let opta = tokens[APIReceivedToken.OPTA_NUMBER]; // which Opta was the request sent from

  console.log(`API Receive from Opta ${opta}: "${data}"`);

   // validate API counter
  if (tokens[APIReceivedToken.REQUEST_COUNTER] < api_receive_counter[opta]) {
    console.log(`Payload discarded (API counter check failed, opta=${opta})`);
    return;
  }

  // validate UNIX timestamp
  let received_timestamp = parseInt(tokens[APIReceivedToken.TIMESTAMP]);
  let timestamp_diff = Math.abs(received_timestamp - get_timestamp());
  if (timestamp_diff > TIMESTAMP_MAX_DIFFERENCE) {
    console.log(`Payload discarded (Timestamp difference too big (${timestamp_diff}), opta=${opta})`);
    return;
  }

  // handle the API request
  let type = tokens[APIReceivedToken.REQUEST_TYPE];
  if (type == APIReceivedType.RELAY_STATES_CHANGED) {
     // relay states were changed by hardware buttons on an Opta
     // so we update the buttons on the webpage
    let new_relay_states = tokens[APIReceivedToken.EXTRA_PARAM];

    for (let i = 0; i < RELAYS_PER_OPTA; i++) {
      relays[opta * RELAYS_PER_OPTA + i] = parseInt(new_relay_states.charAt(i));
    }
    
    // send the relays states to the web client
    io.emit('update_relay_buttons', relays);
  } else if (type == APIReceivedType.ENABLE_BUTTON_INTERRUPTS) {
    // an Opta enabled hardware button interrupts
    hardware_interrupts_enabled = true;
    io.emit('update_interrupts_button', true);

    // enable button interrupts on the other (remaining) Opta's
    let api_send_str = `${APISentType.CHANGE_BUTTON_INTERRUPTS_STATE};1;`;
    for (let i = 0; i < OPTA_COUNT; i++) {
      if (i != opta) {
        api_send(api_send_str, i);
      }
    }
  }

  api_receive_counter[opta]++;
}

function api_send(data, opta) {
  // add API request counter and UNIX timestamp to API data, before encryption
  data = api_send_counter[opta].toString() + ';' + get_timestamp() + ';' + data;
  
  let iv = crypto.randomBytes(IV_SIZE);
  let iv_hex = iv.toString('hex');
  let aes = aes_encrypt_iv(data, iv);
  let hmac = create_hmac(iv_hex + aes);

  let payload = iv_hex + aes + hmac;

  console.log(`API Send to Opta ${opta}: "${data}"`);

  exec(`curl --connect-timeout 5 -H "Payload: ${payload}" http://${opta_ips[opta]}:${opta_port}/`, error => {
    if (error != null) {
      console.log(`cURL Error on Opta ${opta}`);
    }
  });

  api_send_counter[opta]++
}

// AES wrapper functions
function aes_encrypt_iv(input, iv) {
  let cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, iv);
  let output = cipher.update(input, 'utf-8', 'hex');
  output += cipher.final('hex');
  return output;
}

function aes_decrypt_iv(input, iv) {
  let cipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, iv);
  let output = cipher.update(input, 'hex', 'utf-8');
  output += cipher.final('utf-8');
  return output;
}

// HMAC wrapper function
function create_hmac(input) {
  return crypto.createHmac('sha256', HMAC_KEY).update(input).digest('hex');
}

// return unix timestamp
function get_timestamp() {
  return Math.floor(+new Date() / 1000);
}
