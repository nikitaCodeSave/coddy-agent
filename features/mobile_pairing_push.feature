Feature: A phone paired by a QR code gets the agent's notices when nobody looks at Coddy

  The web UI on the computer shows a QR code. A phone that opens its link is
  paired without a password and reaches an open local server under the name a
  proxy in front of it gives (a LAN address, a tailnet name). When the agent
  waits for the person and no tab of Coddy has their attention, the phone gets
  a Web Push notice, encrypted for its browser, and can answer a permission
  from the notification's buttons.

  Background:
    Given an open Coddy server that a proxy names "192.168.1.50"
    And the computer shows a pairing code
    And the phone opens the pairing link under "192.168.1.50"

  Scenario: The paired phone answers a permission from the notification
    Given the phone subscribes to pushes at a fake push service
    When the phone sends a prompt whose turn asks to run a command
    Then the push service receives a notice that decrypts to "permission" for "run_command" with Allow and Reject
    When the phone answers "allow" from the notification
    Then the turn ends with the command allowed
    And the push service receives a notice that decrypts to "turn_finished"

  Scenario: A tab in front of the person keeps the phone quiet
    Given the phone subscribes to pushes at a fake push service
    And a tab of Coddy has the person's attention
    When the phone sends a prompt whose turn asks to run a command
    And the computer answers "allow" in that tab
    Then the turn ends with the command allowed
    And the push service receives nothing
