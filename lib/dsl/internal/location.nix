/*
  Where a DSL error happened, so every error starts `nix-nftypes: <API>: `
  with the builder the caller called (ADR 0009), followed by the field's
  path inside that call, if any. A location is `{ api; path; optionPrefix;
  }`: `api` the public path (`dsl.create.ctCount`, or `dsl.table inet.t`
  for a Table tree), `path` the names inside the call (`[ "chains" "input"
  ]`), and `optionPrefix` the option path the module system prints in its
  own errors, which starts with `api` too: `dsl.create.ctCount.name`, or
  `"dsl.table inet.t".chains.input.prio`, where the module system quotes
  the Table tree's part.

  - `builder names`: a builder under `dsl`, such as `[ "create" "ctCount" ]`.
  - `tableTree family name`: the body of `dsl.table family name`.
  - `within location names`: `location` with `names` appended to its path.
  - `fail location message`: throw `message` at `location`.
*/
{ lib }:

let
  join = lib.concatStringsSep ".";
in
{
  builder = names: {
    api = "dsl.${join names}";
    path = [ ];
    optionPrefix = [ "dsl" ] ++ names;
  };

  tableTree =
    family: name:
    let
      api = "dsl.table ${family}.${name}";
    in
    {
      inherit api;
      path = [ ];
      optionPrefix = [ api ];
    };

  within =
    location: names:
    location
    // {
      path = location.path ++ names;
      optionPrefix = location.optionPrefix ++ names;
    };

  fail =
    location: message:
    throw "nix-nftypes: ${location.api}: ${
      lib.optionalString (location.path != [ ]) "${join location.path}: "
    }${message}";
}
