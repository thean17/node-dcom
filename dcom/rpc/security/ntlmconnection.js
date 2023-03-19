var DefaultConnection = require('../defaultconnection.js');
var AuthenticationVerifier = require('../core/authenticationverifier.js');
var NdrBuffer = require('../../ndr/ndrbuffer.js');
var NTLMAuthentication = require('./ntlmauthentication.js');
var NTLMFlags = require('./ntlmflags.js');
var Security = require('../security.js');
var Type1Message = require('./messages/type1message.js');
var Type2Message = require('./messages/type2message.js');
var Type3Message = require('./messages/type3message.js');
var DefaultConnection = require('../defaultconnection');
const NtlmMessage = require('../security/messages/ntlmmessage');
var util = require('util');
var debug = util.debuglog('dcom');

var contextSerial = 0;
/**
 * NTLM Connection for secure communication
 */
class NTLMConnection extends DefaultConnection
{
  constructor(info)
  {
    super();
    this.authentication = new NTLMAuthentication(info);

    /**
     * @type {NtlmMessage}
     */
    this.ntlm;
  }

  setTransmitLength(transmitLength)
  {
    this.transmitLength = transmitLength;
    this.transmitBuffer = new NdrBuffer([transmitLength]);
  }

  setReceiveLength(receiveLength)
  {
    this.receiveLength = receiveLength;
    this.receiveBuffer = new NdrBuffer([receiveLength]);
  }

  /**
   * Called by {@link DefaultConnection#processIncoming}
   * 
   * @param {import('../core/authenticationverifier')} verifier 
   */
  incomingRebind(verifier)
  {
    console.log('incomingRebind')
    // TODO: Called by DefaultConnection.processIncoming
    switch (verifier.body[8]) {
      case 1:
        this.contextId = verifier.contextId;
        this.ntlm = new Type1Message(verifier.body);
        break;
      case 2:
        console.log('NTLM Message Type: NTLMSSP_CHALLENGE (0x00000002)')
        this.ntlm = new Type2Message(verifier.body);
        break;
      case 3:
        var type2 = this.ntlm;
        this.ntlm = new Type3Message(verifier.body);
        /* FIXME: In the future usentlmv2 and other things that the original
        *  library was reading from properties should be defined diferently
        *  so our lib can also support to manually choose those values
        */
        var usentlmv2 = true;
        if (usentlmv2) {
          this.authentication.createSecurityWhenServer(this.ntlm);
          this.setSecurity(this.authentication.getSecurity());
        }
        break;
      default:
        throw new Error("Invalid NTLM message type");
    }
  }

  /**
   * 
   * @param {{ domain: string, username: string, password: string }} info
   * @return {NtlmMessage}
   */
  outgoingRebind(info, pduType)
  {
    // TODO: The following code perform handshake and exchange
    if (this.ntlm == null) {
      this.contextId = ++contextSerial;
      this.ntlm = this.authentication.createType1(info.domain);
    } else if (this.ntlm instanceof Type1Message) {
      this.ntlm = this.authentication.createType2(this.ntlm);
    } else if (this.ntlm instanceof Type2Message) {
      const type2 = this.ntlm;
      this.ntlm = this.authentication.createType3(type2, info);
      // FIXME: same as incomingRebind
      const usentlmv2 = true;
      if (usentlmv2) {
        this.setSecurity(this.authentication.getSecurity());
      }
    } else if (this.ntlm instanceof Type3Message) {
        // from jinterop-ng
        // int protectionLevel = ntlm.getFlag(NtlmFlags.NTLMSSP_NEGOTIATE_SEAL)
        //         ? Security.PROTECTION_LEVEL_PRIVACY
        //         : ntlm.getFlag(NtlmFlags.NTLMSSP_NEGOTIATE_SIGN)
        //         ? Security.PROTECTION_LEVEL_INTEGRITY
        //         : Security.PROTECTION_LEVEL_CONNECT;
        // return new AuthenticationVerifier(
        //         NtlmAuthentication.AUTHENTICATION_SERVICE_NTLM, protectionLevel,
        //         contextId, ntlm.toByteArray());

      const protectionLevel = new Security().PROTECTION_LEVEL_PRIVACY;

      if (pduType == 0x00) {
        return new AuthenticationVerifier(
          new NTLMAuthentication(info).AUTHENTICATION_SERVICE_NTLM, protectionLevel,
          this.contextId, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        } else if( pduType == 0x0e) {
          let auth = [0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00];
          let empty_body = [...Buffer.alloc(40, 0)];
          let noKeysNoFlags = [0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00];

          let verifier = auth.concat(empty_body);
          verifier = verifier.concat(noKeysNoFlags);
          return new AuthenticationVerifier(
            new NTLMAuthentication(info).AUTHENTICATION_SERVICE_NTLM, protectionLevel,
            this.contextId, verifier);
        }
    } else {
      throw new Error("Unrecognized NTLM message.");
    }

    /**
     * @type {number}
     */
    let protectionLevel;

    if (this.ntlm.getFlag(NTLMFlags.NTLMSSP_NEGOTIATE_SEAL)) {
      protectionLevel = new Security().PROTECTION_LEVEL_PRIVACY;
    } else if (this.ntlm.getFlag(NTLMFlags.NTLMSSP_NEGOTIATE_SIGN)) {
      protectionLevel = new Security().PROTECTION_LEVEL_INTEGRITY;
    } else {
      protectionLevel = new Security().PROTECTION_LEVEL_CONNECT; 
    }

    return new AuthenticationVerifier(this.authentication.AUTHENTICATION_SERVICE_NTLM, protectionLevel,
      this.contextId, this.ntlm.toByteArray());
  }
}

module.exports = NTLMConnection;
