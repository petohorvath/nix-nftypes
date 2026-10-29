/*
  How an error or a type description lists words, so every list reads the
  same way.

  - `conjoin conjunction words`: "a", "a and b", or "a, b, and c", with
    `conjunction`, such as "and" or "or", before the last of `words`.
  - `withValid message label valid`: `message`, followed by the values
    `valid` it accepts, named by `label`: "<message>. Valid <label>: a, b."
*/
{ lib }:

{
  conjoin =
    conjunction: words:
    if builtins.length words <= 2 then
      lib.concatStringsSep " ${conjunction} " words
    else
      "${lib.concatStringsSep ", " (lib.init words)}, ${conjunction} ${lib.last words}";

  withValid =
    message: label: valid:
    "${message}. Valid ${label}: ${lib.concatStringsSep ", " valid}.";
}
