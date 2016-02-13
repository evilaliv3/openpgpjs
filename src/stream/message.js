'use strict';

import util from '../util.js';
import crypto_stream from './crypto.js'
import packet from '../packet';
import packetParser from '../packet/packet.js';
import enums from'../enums.js';
import armor from '../encoding/armor.js';
import config from '../config';
import crypto from '../crypto';
import forge from 'node-forge';
import message from '../message.js';
import * as keyModule from '../key.js';

function MessageStream(keys, file_length, filename, opts) {
  var self = this;
  filename = filename || 'msg.txt';
  filename = util.encode_utf8(filename);
  self.opts = opts || {};
  self.opts.algo = enums.read(enums.symmetric, keyModule.getPreferredSymAlgo(keys));
  self.opts.key = crypto.generateSessionKey(self.opts.algo);
  self.opts.cipherFn = crypto.cipher[self.opts.algo];
  self.opts.prefixRandom = crypto.getPrefixRandom(self.opts.algo);
  self.opts.encoding = self.opts.encoding || 'binary';

  this.headerWritten = false;

  if (config.integrity_protect) {
    self.opts.resync = false;
    var prefixrandom = self.opts.prefixRandom;
    var repeat = new Uint8Array([prefixrandom[prefixrandom.length - 2], prefixrandom[prefixrandom.length - 1]]);
    var prefix = util.concatUint8Array([prefixrandom, repeat]);
    this.hash = forge.sha1.create();
    this.hash.update(util.Uint8Array2str(prefix));
  }

  this.cipher = new crypto_stream.CipherFeedback(self.opts);
  this.fileLength = file_length;
  this.keys = keys;

  var encrypted_packet_header_part2 =  util.concatUint8Array(
    [util.str2Uint8Array(String.fromCharCode(enums.write(enums.literal, self.opts.encoding)) +
                         String.fromCharCode(filename.length) +
                         filename),
     util.writeDate(new Date())]);

  var encrypted_packet_header_part1 = packetParser.writeHeader(enums.packet.literal, encrypted_packet_header_part2.length + this.fileLength);

  this.encrypted_packet_header = new Uint8Array(encrypted_packet_header_part1.length + encrypted_packet_header_part2.length);
  this.encrypted_packet_header.set(encrypted_packet_header_part1, 0);
  this.encrypted_packet_header.set(encrypted_packet_header_part2, encrypted_packet_header_part1.length);

  var packetList = new packet.List(),
    symAlgo = keyModule.getPreferredSymAlgo(this.keys),
    packet_len = this.encrypted_packet_header.length + this.fileLength + this.cipher.blockSize + 2;

  this.keys.forEach(function(key) {
    var encryptionKeyPacket = key.getEncryptionKeyPacket();
    if (encryptionKeyPacket) {
      var pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
      pkESKeyPacket.publicKeyId = encryptionKeyPacket.getKeyId();
      pkESKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.algorithm;
      pkESKeyPacket.sessionKey = self.cipher.sessionKey;
      pkESKeyPacket.sessionKeyAlgorithm = enums.read(enums.symmetric, symAlgo);
      pkESKeyPacket.encrypt(encryptionKeyPacket);
      packetList.push(pkESKeyPacket);
    } else {
      throw new Error('Could not find valid key packet for encryption in key ' + key.primaryKey.getKeyId().toHex());
    }
  });

  this.header = packetList.write();

  if (config.integrity_protect) {
    packet_len += 1 + 20 + 2;
    this.first_packet_header = util.concatUint8Array([packetParser.writeHeader(enums.packet.symEncryptedIntegrityProtected, packet_len), new Uint8Array([1])]);
  } else {
    this.first_packet_header = packetParser.writeHeader(enums.packet.symmetricallyEncrypted, packet_len);
  }

  this.size = this.header.length + this.first_packet_header.length + packet_len;
}

MessageStream.prototype.setOnDataCallback = function(callback) {
  this.onDataFn = callback;
  this.cipher.setOnDataCallback(callback);
}

MessageStream.prototype.setOnEndCallback = function(callback) {
  this.onEndFn = callback;
  this.cipher.setOnEndCallback(callback);
}

MessageStream.prototype.write = function(chunk) {
  if (!(chunk instanceof Uint8Array)) {
    throw new Error('MessageStream.write accepts only Uint8Array');
  }

  if (!this.headerWritten) {
    if (this.onDataFn) {
      this.onDataFn(util.concatUint8Array([this.header, this.first_packet_header]));
    }

    var tmp = new Uint8Array(this.encrypted_packet_header.length + chunk.length);
    tmp.set(this.encrypted_packet_header, 0);
    tmp.set(chunk, this.encrypted_packet_header.length);
    chunk = tmp;

    this.headerWritten = true;
  }

  if (config.integrity_protect) {
    this.hash.update(util.Uint8Array2str(chunk));
  }

  this.cipher.write(chunk);
}

MessageStream.prototype.end = function(cb) {
  if (config.integrity_protect) {
    var mdc_header = String.fromCharCode(0xD3) + String.fromCharCode(0x14);
    this.hash.update(mdc_header);
    var hash_digest = this.hash.digest().getBytes();
    this.cipher.write(util.str2Uint8Array(mdc_header + hash_digest));
  }

  this.cipher.end();
}

module.exports.MessageStream = MessageStream;
