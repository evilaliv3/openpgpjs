'use strict';

import crypto from '../crypto';
import util from '../util.js';

function CipherFeedback(opts) {
  this.algo = opts.algo;
  this.key = (opts.key === undefined) ? crypto.generateSessionKey(this.algo) : opts.key;
  this.cipherFn = (opts.cipherFn === undefined) ? crypto.cipher[this.algo] : opts.cipherFn;
  this.cipher = new this.cipherFn(this.key);
  this.sessionKey = opts.key;
  this.prefixRandom = (opts.prefixRandom === undefined) ? crypto.getPrefixRandom(this.algo) : opts.prefixRandom;
  this.resync = (opts.resync === undefined) ? true : opts.resync;

  this.blockSize = this.cipher.blockSize;
  this.feedbackRegister = new Uint8Array(this.blockSize);
  this.feedbackRegisterEncrypted = new Uint8Array(this.blockSize);

  this._firstBlockEncrypted = false;
  this._eof = false;
  this._previousCiphertext = new Uint8Array(0);
  this._previousChunk = new Uint8Array(0);

  this._buffers = [];
  this._buffered_total = 0;

  this._blocks = [];
  this._blocks.push(new Uint8Array(this.blockSize));
  this._blocks.push(new Uint8Array(this.blockSize));
  this._total = 0;

  this._current_block = 0;
}

CipherFeedback.prototype.setOnDataCallback = function(callback) {
  this.onDataFn = callback;
}

CipherFeedback.prototype.setOnEndCallback = function(callback) {
  this.onEndFn = callback;
}

CipherFeedback.prototype._encryptFirstBlock = function(chunk) {
  var prefixrandom = this.prefixRandom;
  var resync = this.resync;
  var key = this.sessionKey;
  var block_size = this.blockSize;

  var new_prefix = new Uint8Array(prefixrandom.length + 2);
  new_prefix.set(prefixrandom);
  new_prefix[prefixrandom.length] = prefixrandom[block_size-2];
  new_prefix[prefixrandom.length+1] = prefixrandom[block_size-1];
  prefixrandom = new_prefix;

  var ciphertext = new Uint8Array(chunk.length + 2 + block_size * 2);
  var i, n, begin;
  var offset = resync ? 0 : 2;

  // 1.  The feedback register (FR) is set to the IV, which is all zeros.
  for (i = 0; i < block_size; i++) {
    this.feedbackRegister[i] = 0;
  }

  // 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
  //     encryption of an all-zero value.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);
  // 3.  FRE is xored with the first BS octets of random data prefixed to
  //     the plaintext to produce C[1] through C[BS], the first BS octets
  //     of ciphertext.
  for (i = 0; i < block_size; i++) {
    ciphertext[i] = this.feedbackRegisterEncrypted[i] ^ prefixrandom[i];
  }

  // 4.  FR is loaded with C[1] through C[BS].
  this.feedbackRegister.set(ciphertext.subarray(0, block_size));

  // 5.  FR is encrypted to produce FRE, the encryption of the first BS
  //     octets of ciphertext.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

  // 6.  The left two octets of FRE get xored with the next two octets of
  //     data that were prefixed to the plaintext.  This produces C[BS+1]
  //     and C[BS+2], the next two octets of ciphertext.
  ciphertext[block_size] = this.feedbackRegisterEncrypted[0] ^ prefixrandom[block_size];
  ciphertext[block_size + 1] = this.feedbackRegisterEncrypted[1] ^ prefixrandom[block_size + 1];

  if (resync) {
    // 7.  (The resync step) FR is loaded with C[3] through C[BS+2].
    this.feedbackRegister.set(ciphertext.subarray(2, block_size + 2));
  } else {
    this.feedbackRegister.set(ciphertext.subarray(0, block_size));
  }

  // 8.  FR is encrypted to produce FRE.
  this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

  // 9.  FRE is xored with the first BS octets of the given plaintext, now
  //     that we have finished encrypting the BS+2 octets of prefixed
  //     data.  This produces C[BS+3] through C[BS+(BS+2)], the next BS
  //     octets of ciphertext.
  for (i = 0; i < block_size; i++) {
    ciphertext[block_size + 2 + i] = this.feedbackRegisterEncrypted[i + offset] ^ chunk[i];
  }
  this._previousCiphertext = ciphertext.subarray(block_size + 2 - offset, 2*block_size + 2 - offset);
  this._previousChunk = chunk;
  ciphertext = ciphertext.subarray(0, chunk.length + 2 + block_size - offset);
  return ciphertext;
}

CipherFeedback.prototype._encryptBlock = function(chunk) {
  var ciphertext = new Uint8Array(chunk.length + 2),
    block_size = this.blockSize,
    offset = this.resync ? 0 : 2,
    i, n, begin;

  for (n = 0; n < chunk.length + offset; n += block_size) {
    begin = n;
    // 10. FR is loaded with C[BS+3] to C[BS + (BS+2)] (which is C11-C18 for
    // an 8-octet block).
    this.feedbackRegister.set(this._previousCiphertext);

    // 11. FR is encrypted to produce FRE.
    this.feedbackRegisterEncrypted = this.cipher.encrypt(this.feedbackRegister);

    // 12. FRE is xored with the next BS octets of plaintext, to produce
    // the next BS octets of ciphertext. These are loaded into FR, and
    // the process is repeated until the plaintext is used up.
    for (i = 0; i < block_size; i++) {
      var byte;
      if ((n + i - offset) < 0) {
        byte = this._previousChunk[block_size + (n + i - offset)];
      } else {
        byte = chunk[n + i - offset];
      }
      ciphertext[begin + i] = this.feedbackRegisterEncrypted[i] ^ byte;
    }
    this._previousCiphertext = ciphertext.subarray(0, chunk.length);
  }

  this._previousChunk = chunk;
  if (this._eof) {
    ciphertext = ciphertext.subarray(0, chunk.length + offset);
  } else {
    ciphertext = ciphertext.subarray(0, chunk.length);
  }

  return ciphertext;
}

CipherFeedback.prototype.encryptBlock = function(chunk) {
  var ciphertext;
  if (!this._firstBlockEncrypted) {
    ciphertext = this._encryptFirstBlock(chunk);
    this._firstBlockEncrypted = true;
  } else {
    ciphertext = this._encryptBlock(chunk);
  }
  return ciphertext;
};

CipherFeedback.prototype.write = function(chunk) {
  if (!(chunk instanceof Uint8Array)) {
    throw new Error('MessageStream.write accepts only Uint8Array');
  }

  if (chunk.length) {
    this._total += chunk.length;
    this._buffers.push(chunk);
    this._buffered_total += chunk.length;
  }

  while (this._buffered_total >= this.blockSize) {
    this._current_block = (this._current_block == 0) ? 1 : 0;
    var buf = new Uint8Array(this.blockSize);
    var missing = this.blockSize;
    var offset = 0;
    for (var i = 0; i < this._buffers.length; i++) {
      var copy_length = this._buffers[i].length > missing ? missing : this._buffers[i].length;
      buf.set(this._buffers[i].subarray(0, copy_length), offset);
      offset += copy_length;
      missing -= copy_length;
      this._buffered_total -= copy_length;
      if (missing === 0) {
        if (copy_length != this._buffers[i].length) {
          this._buffers[i] = this._buffers[i].subarray(copy_length);
          this._buffers = this._buffers.slice(i);
        } else {
          this._buffers = this._buffers.slice(i + 1);
        }
        this.onDataFn(this.encryptBlock(buf));
        break;
      }
    }
  }
}

CipherFeedback.prototype.end = function() {
  this._eof = true;

  if (this._buffered_total > 0) {
    var buf = new Uint8Array(this._buffered_total);
    var offset = 0;
    for (var i = 0; i < this._buffers.length; i++) {
      buf.set(this._buffers[i], offset);
      offset += this._buffers[i].length;
    }
    this.onDataFn(this.encryptBlock(buf));
  }

  if (this.onEndFn) {
    this.onEndFn();
  }
}

module.exports.CipherFeedback = CipherFeedback;
