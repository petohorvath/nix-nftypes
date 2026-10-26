# Reject statement, which drops a packet and answers the sender.
{ statement, ... }:

{
  /*
    Reject matching packets.

    `reject { type?; code?; }` answers with the reject `type`, such as
    `"icmpx"` or `"tcp reset"`, and its ICMP `code`; null values are
    omitted, so `reject { }` is the reject statement with nft's default
    answer. Returns a reject statement. Throws when the body doesn't
    validate, and for `expr`, pointing to `code`.
  */
  reject = statement.fromFields { name = "reject"; };
}
