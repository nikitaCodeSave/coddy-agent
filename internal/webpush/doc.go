// Package webpush sends Web Push messages to the push service a browser
// subscribed with, using the standard library alone: the aes128gcm message
// encryption of RFC 8291, the VAPID authorization of RFC 8292 and the request
// of RFC 8030. It holds no subscriptions and decides nothing about who gets a
// notice; the caller stores subscriptions and acts on each Result.
package webpush
