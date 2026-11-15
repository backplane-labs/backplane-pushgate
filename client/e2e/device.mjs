// A desktop device on the built package, driven by tests/tsclient_test.go:
// it subscribes with the sender key it is given, prints its address, then
// opens, acknowledges and prints the first message. One JSON object per line.
import { PushgateClient, decrypt, generateContentKeys } from '../dist/index.js';
import { createDeviceKey } from '../dist/testing.js';

const [url, senderKey] = process.argv.slice(2);
const keys = await generateContentKeys();
const print = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);

const client = new PushgateClient({
  url,
  device: await createDeviceKey(),
  onNotification: async (n) => {
    const plaintext = new TextDecoder().decode(await decrypt(keys, n.data));
    print({ plaintext, topic: n.topic ?? '', urgency: n.urgency });
    setTimeout(() => {
      client.stop();
      process.exit(0);
    }, 200); // the ack leaves first
  },
  onStatus: async (s) => {
    if (s.state === 'online' && client.subscriptions.length === 0) {
      const sub = await client.subscribe(senderKey);
      print({ subscribed: { endpoint: sub.endpoint, p256dh: keys.p256dh, auth: keys.auth } });
    }
    if (s.final && s.code !== 1000) process.exit(1);
  },
});

client.start();
