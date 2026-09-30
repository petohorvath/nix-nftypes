/*
  Drop null-valued attributes. Builders call this before wrapping a body
  into its tagged shape so omitted optional arguments do not appear as
  `{ foo = null; }` in intermediate values. The renderers also strip them,
  but doing it here keeps debug output readable.
*/
{ lib }:

lib.filterAttrs (_: v: v != null)
