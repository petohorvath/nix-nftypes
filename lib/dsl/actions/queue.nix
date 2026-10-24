# Queue statement, which hands packets to a userspace program.
{ statement, ... }:

{
  /*
    Pass matching packets to a userspace queue.

    `queue { num?; flags?; }` takes the optional queue number (or range)
    and queue flags; `queue { }` uses every default. Returns a queue
    statement, and throws when the body doesn't validate.
  */
  queue = statement.fromFields { name = "queue"; };
}
