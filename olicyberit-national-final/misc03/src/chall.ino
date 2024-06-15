#include "ChaCha.h"
#define MAX_DATA_SIZE 64

struct fsm_state_s {
  bool key_set = false;
  bool nonce_set = false;
} protocol_state;

struct message_s {
  uint8_t code;
  int8_t param;
  uint8_t len;
  char data[MAX_DATA_SIZE];
};

struct message_s in_msg;
struct message_s out_msg;

enum MessageCode {
  KEYSET    = 0x74,
  NONCESET  = 0x11,
  STORE     = 0xC1,
  RESET     = 0xB8,
  ACK       = 0x14,
  ERROR     = 0xFF
};

char KEY[32]  = {0};
char IV[8]    = {0};
ChaCha cipher;

char FLAG[40] = {0};

void readMessage(struct message_s *m) {
  while (true) {
    if (Serial.available() > 0) {
      m->code = Serial.read();
      break;
    }
  }
  while (true) {
    if (Serial.available() > 0) {
      m->param = Serial.read();
      break;
    }
  }
  while (true) {
    if (Serial.available() > 0) {
      m->len = Serial.read();
      break;
    }
  }
  int i = 0;
  while (i < m->len) {
    if (Serial.available() > 0) {
      m->data[i++] = Serial.read();
    }
  }
}

void sendMessage(struct message_s *m) {
  Serial.write((char)m->code);
  Serial.write((char)m->param);
  Serial.write((char)m->len);
  int i = 0;
  while (i < m->len)
    Serial.write((char)m->data[i++]);
}

void prepareAckMessage() {
  out_msg.code = MessageCode::ACK;
  out_msg.param = 0;
  out_msg.len = 0;
}

void prepareErrorMessage() {
  out_msg.code = MessageCode::ERROR;
  out_msg.param = 0;
  out_msg.len = 0;
}

void handleMessage() {
  switch (in_msg.code) {
    case MessageCode::KEYSET:
      for (int i = 0; i < 32; i++) {
        KEY[i] = in_msg.data[i];
      }
      cipher.setKey(KEY, sizeof(KEY));
      protocol_state.key_set = true;
      break;
    case MessageCode::NONCESET:
    for (int i = 0; i < 8; i++) {
        IV[i] = in_msg.data[i];
      }
      cipher.setIV(IV, sizeof(IV));
      protocol_state.nonce_set = true;
      break;
    case MessageCode::STORE:
      if (!protocol_state.key_set || !protocol_state.nonce_set) {
        prepareErrorMessage();
        return;
      }
      cipher.decrypt(in_msg.data, in_msg.data, in_msg.len);
      for (int i = 0; i < in_msg.len; i++) {
        FLAG[10 * in_msg.param + i] = in_msg.data[i];
      }
      break;
    case MessageCode::RESET:
      cipher.clear();
      for (int i = 0; i < 32; i++) {
        KEY[i] = 0;
      }
      for (int i = 0; i < 8; i++) {
        IV[i] = 0;
      }
      protocol_state.key_set = protocol_state.nonce_set = false;
      break;
    default:
      break;
  }
  prepareAckMessage();
}

void setup() {
  Serial.begin(9600);
  cipher = ChaCha::ChaCha();
}

void loop() {
  readMessage(&in_msg);
  handleMessage();
  sendMessage(&out_msg);
}
