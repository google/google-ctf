const module = new WebAssembly.Module(read('/tmp/pwn.wasm', 'binary'));
const instance = new WebAssembly.Instance(module, {});
console.log(`0x${instance.exports.pwn().toString(16)}`);
