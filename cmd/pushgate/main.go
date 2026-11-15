// pushgate is a Web Push service (RFC 8030) for desktop clients without an
// operating system push: senders post to a subscription's endpoint, a
// client keeps one WebSocket and receives its messages.
package main

import pushgate "github.com/backplane-labs/backplane-pushgate"

func main() { pushgate.Main() }
