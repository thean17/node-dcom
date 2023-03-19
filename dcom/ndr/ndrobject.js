const NdrBuffer = require("./ndrbuffer.js");
var NetworkDataRepresentation = require("./networkdatarepresentation.js");

function NdrObject (){
  this.opnum = -1;
  this.value;
};

NdrObject.prototype.write = function (ndr){};

NdrObject.prototype.read = function (ndr){};

NdrObject.prototype.getOpnum = function getOpnum(){
  return this.opnum;
}

/**
 * 
 * @param {NetworkDataRepresentation} ndr 
 * @param {NdrBuffer} dst 
 */
NdrObject.prototype.encode = function (ndr, dst){
  ndr.buf = dst;
  this.write(ndr);
}

NdrObject.prototype.decode = async function (ndr, src){
  ndr.buf = src;
  await this.read(ndr);
}

module.exports = NdrObject;
