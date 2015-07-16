var util = require('../util.js'),
  crypto_stream = require('./crypto.js'),
  packet = require('../packet'),
  enums = require('../enums.js'),
  armor = require('../encoding/armor.js'),
  config = require('../config'),
  crypto = require('../crypto'),
  keyModule = require('../key.js'),
  message = require('../message.js');

function MessageStream(keys, file_length, filename, opts) {
  var self = this;
  filename = filename || 'msg.txt';
  filename = util.encode_utf8(filename);
  self.opts = opts || {};
  self.opts.algo = enums.read(enums.symmetric, keyModule.getPreferredSymAlgo(keys));
  self.opts.key = crypto.generateSessionKey(self.opts.algo);
  self.opts.cipherFn = crypto.cipher[self.opts.algo];
  self.opts.prefixRandom = crypto.getPrefixRandom(self.opts.algo);
  if (config.integrity_protect) {
    self.opts.resync = false;
    var prefixrandom = self.opts.prefixRandom;
    var prefix = prefixrandom + prefixrandom.charAt(prefixrandom.length - 2) + prefixrandom.charAt(prefixrandom.length - 1);
    this.hash = crypto.hash.forge_sha1.create();
    this.hash.update(prefix);
  }

  this.cipher = new crypto_stream.CipherFeedback(self.opts);
  this.fileLength = file_length;
  this.keys = keys;

  encrypted_packet_header_part2 = util.str2Uint8Array(
    String.fromCharCode(enums.write(enums.literal, 'utf8')) +
    String.fromCharCode(filename.length) +
    filename +
    util.writeDate(new Date())
  );

  encrypted_packet_header_part1 = util.str2Uint8Array(
    packet.Packet.writeHeader(enums.packet.literal, encrypted_packet_header_part2.length + this.fileLength)
  );

  this.encrypted_packet_header = new Uint8Array(encrypted_packet_header_part1.length + encrypted_packet_header_part2.length);
  this.encrypted_packet_header.set(encrypted_packet_header_part1, 0);
  this.encrypted_packet_header.set(encrypted_packet_header_part2, encrypted_packet_header_part1.length);
}

MessageStream.prototype.setOnDataCallback = function(callback) {
  this.onDataFn = callback;
  this.cipher.setOnDataCallback(callback);
}

MessageStream.prototype.setOnEndCallback = function(callback) {
  this.onEndFn = callback;
  this.cipher.setOnEndCallback(callback);
}

MessageStream.prototype.getHeader = function() {
  var that = this,
    packetList = new packet.List(),
    symAlgo = keyModule.getPreferredSymAlgo(this.keys);

  this.keys.forEach(function(key) {
    var encryptionKeyPacket = key.getEncryptionKeyPacket();
    if (encryptionKeyPacket) {
      var pkESKeyPacket = new packet.PublicKeyEncryptedSessionKey();
      pkESKeyPacket.publicKeyId = encryptionKeyPacket.getKeyId();
      pkESKeyPacket.publicKeyAlgorithm = encryptionKeyPacket.algorithm;
      pkESKeyPacket.sessionKey = that.cipher.sessionKey;
      pkESKeyPacket.sessionKeyAlgorithm = enums.read(enums.symmetric, symAlgo);
      pkESKeyPacket.encrypt(encryptionKeyPacket);
      packetList.push(pkESKeyPacket);
    } else {
      throw new Error('Could not find valid key packet for encryption in key ' + key.primaryKey.getKeyId().toHex());
    }
  });
  var packet_len = this.encrypted_packet_header.length + this.fileLength + this.cipher.blockSize + 2,
    header = packetList.write(),
    first_packet_header;

  if (config.integrity_protect) {
    packet_len += 2 + 20 + 1;
    first_packet_header = packet.Packet.writeHeader(enums.packet.symEncryptedIntegrityProtected, packet_len) + String.fromCharCode(1);
  } else {
    first_packet_header = packet.Packet.writeHeader(enums.packet.symmetricallyEncrypted, packet_len);
  }
  return util.str2bin(header + first_packet_header);
}

MessageStream.prototype.write = function(chunk) {
  if (typeof chunk == 'string') {
    chunk = util.str2Uint8Array(chunk);
  }
  
  if (this.encrypted_packet_header) {

    if (this.onDataFn)
        this.onDataFn(this.getHeader());

    var tmp = new Uint8Array(this.encrypted_packet_header.length + chunk.length);
    tmp.set(this.encrypted_packet_header, 0);
    tmp.set(chunk, this.encrypted_packet_header.length);
    chunk = tmp;
    this.encrypted_packet_header = null;
  }
  if (config.integrity_protect) {
    this.hash.update(util.Uint8Array2str(chunk));
  }

  this.cipher.write(util.Uint8Array2str(chunk)); 
}

MessageStream.prototype.end = function(cb) {
  if (config.integrity_protect) {
    var mdc_header = String.fromCharCode(0xD3) + String.fromCharCode(0x14);
    this.hash.update(mdc_header);
    var hash_digest = this.hash.digest().getBytes();
    this.cipher.write(mdc_header + hash_digest);
  }

  this.cipher.end();
}

module.exports.MessageStream = MessageStream;
