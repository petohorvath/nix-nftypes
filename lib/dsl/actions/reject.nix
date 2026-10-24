# Reject statement, which drops a packet and answers the sender.
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  rename = import ../internal/rename.nix { inherit lib; };
in
{
  /*
    Reject matching packets.

    `reject { type?; code?; }` answers with the reject `type`, such as
    `"icmpx"` or `"tcp reset"`, and its ICMP `code`; null values are
    omitted, so `reject { }` is the reject statement with nft's default
    answer. Returns a reject statement. Throws for `expr`, pointing to
    `code`.
  */
  reject = rename.statementBuilder "reject" (
    renameBody:
    {
      type ? null,
      code ? null,
    }:
    {
      reject = compact (renameBody {
        inherit type code;
      });
    }
  );
}
