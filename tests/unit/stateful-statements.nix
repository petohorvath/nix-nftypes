# The `stmt` of a set, a map, a set or map statement, and a meter takes
# only a Stateful statement: an inline counter, quota, limit, ct count, or
# last, as nft's `STMT_F_STATEFUL` marks one. nft rejects any other there,
# a Reference included. Taking any statement also made the schema a cycle
# that overflowed the stack when NixOS rendered an option's documentation.
{ lib, nftlib, ... }:
let
  inherit (nftlib) dsl types validate;

  scope = {
    family = "inet";
    table = "t";
  };

  set = stmt: {
    add.set = scope // {
      name = "s";
      type = "ipv4_addr";
      inherit stmt;
    };
  };

  # Whether rendering the documentation of an option of `type` finishes.
  documents =
    type:
    let
      docs =
        lib.optionAttrSetToDocList
          (lib.evalModules {
            modules = [ { options.o = lib.mkOption { inherit type; }; } ];
          }).options;
    in
    builtins.deepSeq docs (docs != [ ]);

  rejected = msg: {
    expectedError = {
      type = "ThrownError";
      inherit msg;
    };
  };

  notStateful = "is not of type `stateful statement \\(one of: \"counter\", \"ct count\", \"last\", \"limit\", \"quota\"\\)'";
in
{
  testSetTakesInlineStatefulStatements = {
    expr =
      (validate types.command (set [
        { counter = null; }
        {
          counter = {
            packets = 0;
            bytes = 0;
          };
        }
        { quota.val = 10; }
        {
          limit = {
            rate = 1;
            per = "second";
          };
        }
        { "ct count".val = 2; }
        { last = null; }
        { last.used = 5; }
      ])).add.set.name;
    expected = "s";
  };

  testSetRejectsStatelessStatement = rejected notStateful // {
    expr = validate types.command (set [ { log = null; } ]);
  };

  # A Reference fails at the field: only the inline form is stateful.
  testSetRejectsReference =
    rejected "stmt\\.\"\\[definition 1-entry 1\\]\"\\.counter' is not of type `null literal or \\(inline counter with packets and bytes\\)'"
    // {
      expr = validate types.command (set [ { counter = "c"; } ]);
    };

  testMeterRejectsVerdict = rejected notStateful // {
    expr = validate types.statement {
      meter = {
        name = "m";
        key.payload = {
          protocol = "ip";
          field = "saddr";
        };
        stmt.accept = null;
      };
    };
  };

  testSetStmtRejectsStatelessStatement = rejected notStateful // {
    expr = dsl.setStmt {
      op = "add";
      element = dsl.fields.ip.saddr;
      set = "s";
      statements = [ (dsl.log { }) ];
    };
  };

  testMapStmtRejectsReference =
    rejected "dsl\\.mapStmt\\.stmt\\.\"\\[definition 1-entry 1\\]\"\\.quota' is not of type"
    // {
      expr = dsl.mapStmt {
        op = "add";
        key = dsl.fields.ip.saddr;
        data = 1;
        map = "m";
        statements = [ (dsl.quota.ref "q") ];
      };
    };

  testTableTreeSetRejectsStatelessStatement = rejected notStateful // {
    expr = nftlib.toJson (
      dsl.ruleset [
        (dsl.table "inet" "t" {
          sets.s = {
            type = "ipv4_addr";
            statements = [ dsl.accept ];
          };
        })
      ]
    );
  };

  testStatementOptionDocuments = {
    expr = map documents [
      types.statement
      types.command
      types.ruleset
      types.addObject
      types.readBackObject
      types.objectBodies.setBody
      types.statementBodies.meterBody
      (types.statementOf [ "set" ])
    ];
    expected = [
      true
      true
      true
      true
      true
      true
      true
      true
    ];
  };
}
