'use strict';

const seen = new Set();
for (const className of ['NSDictionary', '__NSDictionaryI', '__NSDictionaryM', '__NSFrozenDictionaryM', '__NSDictionary0', '__NSSingleEntryDictionaryI']) {
  const klass = ObjC.classes[className];
  if (!klass) continue;
  for (const selector of ['- objectForKey:', '- objectForKeyedSubscript:', '- valueForKey:']) {
    const method = klass[selector];
    if (!method) continue;
    const address = method.implementation.toString();
    if (seen.has(address)) continue;
    seen.add(address);
    Interceptor.attach(method.implementation, {
      onEnter(args) {
        this.match = false;
        try {
          const key = new ObjC.Object(args[2]).toString();
          if (key !== 'com.apple.afc2') return;
          this.match = true;
          this.receiver = new ObjC.Object(args[0]).$className;
          console.log(JSON.stringify({event: 'LOOKUP', className, selector, receiver: this.receiver}));
        } catch (_) {}
      },
      onLeave(retval) {
        if (this.match) console.log(JSON.stringify({event: 'RESULT', receiver: this.receiver, value: retval.toString()}));
      }
    });
  }
}

for (const symbol of ['CFDictionaryGetValue', 'CFDictionaryContainsKey']) {
  const address = Module.findGlobalExportByName(symbol);
  if (!address) continue;
  Interceptor.attach(address, {
    onEnter(args) {
      this.match = false;
      try {
        if (new ObjC.Object(args[1]).toString() !== 'com.apple.afc2') return;
        this.match = true;
        console.log(JSON.stringify({event: symbol, dictionary: new ObjC.Object(args[0]).$className}));
      } catch (_) {}
    },
    onLeave(retval) {
      if (this.match) console.log(JSON.stringify({event: symbol + '_RESULT', value: retval.toString()}));
    }
  });
}

console.log(JSON.stringify({event: 'READY', hooks: seen.size}));
