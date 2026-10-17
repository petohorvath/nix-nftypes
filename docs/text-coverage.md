# Text renderer coverage

`lib/text/` spells schema-shaped values in nftables' native text grammar.
`lib/table.nix` owns table-tree validation and block emission, retaining each
chain's rules throughout preparation. Both are pure Nix; they do not invoke
`nft`.

`lib/text/limit.nix` owns limit clauses for inline statements, named objects,
and positional `create limit` commands, including unit safety and burst defaults.

The JSON renderer is the compatibility target. Text support is tested
separately because JSON and text have different grammars, quoting rules, and
runtime behavior.

## Render modes

| Function            | Form                                 |
| ------------------- | ------------------------------------ |
| `toText`            | compact imperative commands          |
| `toTextPretty`      | readable imperative commands         |
| `toTextBlock`       | compact contents of one table block  |
| `toTextBlockPretty` | readable contents of one table block |

Imperative output contains commands such as `add table`, `add chain`, and
`add rule`. Block output accepts one `dsl.table` node, omits the table wrapper,
keeps the table's `flags` and `comment`, and emits named objects and chains in
block syntax with rules folded into their parent chains. It rejects top-level `elements.<name>` entries because the
standalone `element` command has no representation inside table-block grammar;
initial elements remain supported inside their set/map definitions.

## Executable evidence

| Check                                    | Current scope                                                                                                                                                                                         | Failure policy                                                                                                              |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `nix-unit`: text parity suite            | expected strings for statements, expressions, objects, and commands                                                                                                                                   | any mismatch fails                                                                                                          |
| `nix-unit`: schema/text drift assertions | every schema statement/expression/object tag has a renderer registration                                                                                                                              | missing registration fails                                                                                                  |
| `nix-unit`: block parity suite           | 38 exact-output, structure, validation, ordering, and rejection assertions through the public table interface                                                                                         | any mismatch fails                                                                                                          |
| `integration-text-block`                 | 6 table cases in compact and pretty form through `nft -c -f`, including chain/object references and inline/named limits                                                                               | any parse failure fails, as does a missing or unexpected case                                                               |
| `integration-render-equivalence`         | every Integration case loaded through JSON, compact text, pretty text, and, for a case built from a Table tree, block form, each in its own network namespace, then compared using `nft list ruleset` | a load failure or listing difference fails, as do a missing or unexpected case and a named exclusion that no longer differs |
| `integration-parse-check`                | every expected string in the text and block parity suites, and every Field leaf rendered as text, through `nft -c -f` with the state it refers to                                                     | a rejection fails unless it's an expected rejection, which must still fail with its error                                   |

Each check uses the `nft` binary of the nixpkgs it evaluates: the locked input
or one of the project policy's stable and unstable pins.

The equivalence suite is strong evidence for its Integration cases. It is not
a universal 1:1 guarantee for every schema value.

## Render equivalence exclusions

`tests/fixtures/render-equivalence.nix` lists every exception, and the suite
asserts each one still holds, so a stale exception fails:

- **Refusals.**
  - Block form refuses `standalone-elements-after-set`, because block grammar
    has no standalone `element` command.
  - Every text form refuses `commented-set-and-map`, because nft's JSON parser
    ignores a set or map comment (see [Fields JSON input ignores](#fields-json-input-ignores)).
- **Per-version expectations.** `ct-count-objects` uses the `ct count` object
  from nftables 1.1.7, so the suite expects every form to be rejected on an
  older `nft`.
- **Known differences.**
  - `typeof-verdict-map`, every text form: nft's JSON parser declares a map
    with a typeof key and a `verdict` value with `type`, so its JSON listing
    reads `type ipv4_addr : verdict`, while text lists the `typeof ip saddr`
    it was written with. The maps match the same keys. See
    [typeof declarations](#typeof-declarations).
- **Pending entries.** A form that still loads something other than its JSON,
  until the open ticket under #24 that the entry names fixes it. None today.

A case built with `dsl.ruleset` commands only has no block form, because block
form renders only Table trees.

`last used <time>` lists the time since the rule last matched, and an
element's `expires <time>` lists the time left until it times out. Both change
between a load and its listing, so the probe drops the seconds and milliseconds
of each such time before the comparison: `last used 1d3ms` lists as
`last used 1d~`.

## Coverage limits

### JSON-only names and values

The JSON API can represent strings without relying on the text lexer's keyword
and identifier rules. A JSON-valid object name may therefore lack a safe text
spelling. For example, the text grammar reserves `offload` in the
flowtable-name and flowtable-reference positions, so a flowtable named
`offload` loads only through JSON.

The same applies to map datatypes. The text renderer accepts identifier-shaped
datatypes only, so it rejects a map whose `map` value is an object type with a
space, such as `"ct count"` or `"ct timeout"`. Define such a map with JSON. A
statement that looks it up (`ct count name meta mark map @m`) and inline map
references still render to text.

A tunnel match (`tunnel id`, `tunnel path`) leaves nft's lexer reading tunnel
keywords for the rest of the input, in nftables 1.1.6 and 1.1.7. A later
command that names a chain `ingress` or `egress` then fails to parse, quoted
or not, so imperative text fails when such a chain has a rule after a tunnel
match. Block form and JSON are unaffected.

### typeof declarations

A typeof set renders as `typeof <expression>`. nft's text grammar declares both
sides of a map with one keyword, so a map renders as follows:

| Key      | Value                                          | Text                          |
| -------- | ---------------------------------------------- | ----------------------------- |
| datatype | datatype                                       | `type ipv4_addr : mark`       |
| typeof   | typeof                                         | `typeof ip saddr : meta mark` |
| typeof   | datatype or object kind                        | `typeof ip saddr : verdict`   |
| datatype | typeof                                         | Refusal                       |
| datatype | `ct helper`, `ct timeout`, or `ct expectation` | Refusal                       |

After a typeof key, nft's text grammar takes a value name only for `verdict`
and object kinds such as `counter` or `ct helper`; another name fails to parse
or loads as a different declaration, so give that value as `{ typeof = …; }`.
nft lists a map of ct helpers, timeouts, or expectations with a datatype key,
as in `type inet_service : ct helper`, but parses one only with a typeof key,
so the text renderer refuses the datatype form and names the field (`map
type`). For `verdict`,
nft's JSON parser drops the typeof and declares the map with `type`, a Known
difference. nft's own JSON listing names a typeof map's value by
datatype (`"map": "mark"`), so text can't spell every Read-back map.

### Fields JSON input ignores

nft's JSON parser ignores these fields, although `nft list` shows them for a
ruleset loaded through text:

- a set or map `comment`;
- an element statement: the `counter`, `quota`, `limit`, or `last` key that
  nft lists beside an element's `val`, or a raw `stmt` list.

The schema accepts the comment and the listed element keys as Read-back
shapes. Text would load them while JSON drops them, so the text renderer
refuses them and names the field (`set comment`, `map comment`, or `element
counter`). Set-level statements, such as `counter;`, render as before.

nft's JSON parser ignores a listed rule's `handle` too, while text reads it as
a position: `rule … handle 7` loads after rule 7, or fails with `No such file
or directory` when the chain has no rule 7. So the text renderer leaves the
handle off a listed rule, and a Read-back with rules loads as text what it
loads as JSON.

On `add rule`, text can't load what JSON loads on every tested nft: nftables
1.1.6's JSON parser ignores the handle and appends the rule, while 1.1.7's,
like text, adds the rule after the rule with that handle. The text renderer
refuses the handle and names the field (`add rule handle`). The schema rejects
it, so only raw input reaches the renderer with one (see the
[schema coverage](spec-coverage.md#rule-handles-on-add-rule)). `insert`,
`replace`, `delete`, and `destroy` keep the handle, which JSON and text use
alike.

A ct expression's `family` is ignored too, but text still writes it, as in
`ct original ip saddr 10.0.0.1`: in an inet table that text loads, while the
JSON form fails with `cannot determine ip protocol version`, in nftables
1.1.6 and 1.1.7. In an ip or ip6 table both forms load the same rule. See the
[schema coverage](spec-coverage.md#3-read-backinput-asymmetries).

### Statement spellings

Several statements take a text spelling that differs from their JSON fields
but loads the same rule:

| JSON                                                                  | Text                                                                                                                       |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| limit with no `rate_unit`, or `packets`                               | `limit rate 10/second`, burst in packets; JSON ignores `burst_unit`                                                        |
| limit with a byte `rate_unit` and no `burst_unit`                     | `burst 5 bytes`                                                                                                            |
| limit `burst = 0`                                                     | no burst: JSON turns a packet burst of 0 into 5, as text does without one                                                  |
| quota with no `val_unit` or `used_unit`, quota object with no `bytes` | `bytes`, and `0 bytes`                                                                                                     |
| log `flags`                                                           | one `flags` clause per group, as in `flags tcp sequence,options flags skuid`                                               |
| last `used = -1`, `used = N`                                          | `last used never`, `last used Nms`                                                                                         |
| exthdr with no `field`                                                | `exthdr frag`                                                                                                              |
| queue `num` other than a number or range                              | `queue to symhash mod 2`                                                                                                   |
| queue `flags` with no `num`                                           | `queue bypass`                                                                                                             |
| fwd with `family` and `addr`                                          | `fwd ip to 192.0.2.1 device "eth0"`; JSON ignores either alone                                                             |
| snat or dnat with `family` and `port` but no `addr`                   | `snat to :80`: nft's text takes no family there, and JSON loads the table's family, in an inet table for either NAT family |
| NAT `flags` with `netmap`                                             | `snat ip prefix to 10.0.0.0/24`                                                                                            |
| NAT `type_flags` with `concat`                                        | `snat ip addr . port to …`                                                                                                 |
| NAT `type_flags` `prefix` or `interval`                               | nothing: `prefix` only changes nft's listing, and nft derives `interval` from the map                                      |
| a negative integer                                                    | quoted, `"-1"`, the symbol JSON loads                                                                                      |

The text renderer refuses the values that nft's text grammar can't spell with
their JSON meaning, and names the field:

- `nat flags`: `netmap` with a port, with another flag, or on `masquerade`
  and `redirect`. `prefix to` takes no port, and nft's text sets the flags
  written after it in place of `netmap`.
- `nat type_flags`: `concat` without a `family`, or with a port.
- `nat family`: a family other than its ip or ip6 table's on an `snat` or
  `dnat` without an address. nft's JSON parser fails on it ("Operation not
  supported"), while text, which can't write the family, would load.
- `exthdr name`: an existence check of `rt0`, `rt2`, or `srh`; nft's text
  checks only `hbh`, `rt`, `frag`, `dst`, and `mh`.
- `last used`: a time below -1, which JSON loads as a huge one.
- `log flags`: a value that is no log flag.

### Object spellings

Some objects take a text spelling that differs from their JSON fields but
loads the same object:

| JSON                                                      | Text                                                                                                                                                 |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| counter object with only `packets` or only `bytes`        | `packets 5 bytes 0`: nft's text takes the counts only as a pair, and JSON loads a missing one as 0                                                   |
| synproxy object                                           | `mss 1460; wscale 7; timestamp sack-perm`: nftables 1.1.7 misreads `mss 1460 wscale 7` on one line, loading `wscale` as 0, or as 8 after `timestamp` |
| `create` of a counter, quota, limit, synproxy, or secmark | positional values, as in `create counter inet t c packets 5 bytes 0`: nft's text takes no braces there                                               |
| ct expectation `timeout`                                  | milliseconds, `timeout 60ms`                                                                                                                         |

The positional `create` forms have no comment clause, so the text renderer
refuses a comment on one and names the field, such as `create quota comment`.
Use `add`, which takes the comment in braces. `create secmark` also requires
its context, which JSON's `create` doesn't, so the renderer refuses one
without, naming the field `create secmark context`.

### Tunnel objects

The text renderer refuses a tunnel object in every command and in a listed
ruleset, and names the field `tunnel`. nft's JSON parser writes a tunnel's
`dport` into its `sport`, so text that loads the tunnel as written would load
a different ruleset from its JSON form. The schema accepts a tunnel only as
Read-back (see [`spec-coverage.md`](spec-coverage.md#commands-nft-mishandles)).

### Listing metadata and meters

A listing from `nft -j list` starts with a `metainfo` object, which holds
nft's version and JSON schema version. nft's JSON parser ignores it, so text
drops it, and the text form loads what the JSON form loads. No command takes
a metainfo: nft rejects `list metainfo` in text and JSON, so the text renderer
refuses a command that names one, such as `list metainfo`, and names the field
(`list metainfo`).

The text renderer refuses a listed `meter` object and names the field
`meter`. nft's text has no meter object, and nft's JSON parser rejects a
listed one with `Unknown object passed to add command`, in nftables 1.1.6 and
1.1.7. Neither version lists one: the dynamic set that a `meter` statement
creates lists as a `set`. `flush meter` and `list meter` render as before.

### Rare or kernel-dependent constructs

Expected-string tests cover more syntax than the isolated live-parser suite can
materialize. Less common statements may require kernel modules, device state,
or object support unavailable in an unprivileged network namespace. The parse
check sends each expected string through `nft`, but not every variant is
real-loaded.

### Command state

Commands using handles, indexes, reset/list output, or referenced objects can
be syntactically valid while requiring state that a check-only or empty
namespace does not contain. The parse check loads that state from a
per-pin context in `tests/fixtures/parse-check.nix` before checking the pin.

### Raw input

The text renderer accepts raw attrsets for escape-hatch use, but it is not a
schema validator. Defensive token and string assertions block known injection
classes, yet callers should still validate raw configuration with
`nftlib.validate nftlib.types.ruleset`.

### Quoting and safety

Several text positions have no general escape syntax. The schema and renderer
therefore reject unsafe quoted strings, interface names, bare scalar tokens,
references, unit names, and priorities instead of emitting ambiguous text.
JSON may be able to carry a value that the text path intentionally refuses.

Text quotes every value it knows to be an interface name, so the value loads
as exactly the JSON string. Bare, `010` loaded as `8`, `a|b` as `c`, and
`$lan` took a host `define`. The quoted positions are:

- set and map elements whose declared type or typeof key is `ifname`,
  including the interface-name parts of a concatenation;
- the right side of a match, vmap, or map lookup on an interface name
  (`meta iifname`, `oifname`, `sdifname`, `ibrname`, `obrname`, and fib
  `oifname`);
- chain and flowtable devices, and the device of a `dup` or `fwd` statement.

An OS fingerprint is a quoted string too: the right side of an `osf name` or
`osf version` match, and the elements of a set whose typeof key is one, are
quoted, as in `osf version == "Linux:3.0"`. Bare, nft's text can't parse
`Linux:3.0`.

An interface name needs only the quoted-string rules and the kernel's own name
rules: 1 to 15 bytes, not `.` or `..`, and no `/`, `:`, or whitespace. The
kernel reads bytes as Latin-1, so whitespace includes byte 0xA0, which UTF-8
uses in U+00A0 (no-break space), U+00E0, and other characters. `@name`
references and the catch-all element `*` keep their bare spelling, as in JSON.

Where the renderer can't tell a value's type, as in an `add element` command,
which doesn't carry its set's type, the value keeps the bare-token check, and
a string must be one that nft's lexer reads as that string: a name, an IPv4,
IPv6, or MAC address, a `@name` reference, or `*`. The renderer refuses any
other string, because bare, `010` loads as `8`, `0x10` as `16`, `a|b` as `c`,
and `$lan` takes a host `define`. Give a number as an integer, or declare the
elements with the set, whose type lets the renderer quote them. Time strings
such as `1h` and class ids such as `1:2` also lex as one token, but the
renderer refuses them too.

The text renderer checks every value it writes bare, including enum,
closed-set, and integer fields such as a chain `policy`, a log `level`, or a
set `size`: each must be an integer, or a string that passes the bare-token
check. The bare-token check refuses whitespace, `,`, `;`, `{`, `}`, `"`, `\`,
`#`, control characters, and any byte above 0x7F, which nft's lexer reads as
junk outside a quoted string. A quoted string, such as a comment, takes byte
0xA0 and other bytes above 0x7F, which nft loads as written.

A log prefix is the one quoted string that nft's text expands: it replaces
`$name` with the value of a `define`, fails on an undefined name, and has no
escape for `$`, while JSON loads the prefix literally. nft also requires a
prefix of 1 to 127 bytes. `types.logPrefix` and the text renderer therefore
refuse a log prefix containing `$` or outside that length. Give a literal `$`
through a raw JSON attrset.

A bare expression string containing `/`, such as `"198.51.100.7/0"`, is
refused, and the Refusal points to `exprs.prefix` (`dsl.expr.prefix`). nft's
JSON parser rejects such a string as a hostname, while text would load it as
a prefix, so a typo could widen a match to every address.

Each of these Refusals names the field, such as `chain policy`, `match
right`, or `element`.

## Support policy

Use `toJson` when:

- parser compatibility is more important than human-readable output;
- names or values interact with text keywords;
- the construct is listed as a text limitation;
- exact text-path evidence does not exist.

Use `toText*` for cases covered by the parity/live suites or after adding a
focused parser fixture for the required construct.

When extending the renderer:

1. add the expected text to the parity suite;
2. add or update a live-parser case where the environment can support it;
3. add an Integration case, which Render equivalence loads in every form;
4. record any necessary named exclusion with its reason, as a Known
   difference or as a pending entry naming its fix ticket.
