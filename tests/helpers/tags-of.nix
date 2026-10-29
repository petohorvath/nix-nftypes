/*
  `tagsOf type`: the tags of a tagged union, such as `types.statement`,
  or of every tagged union among the branches of an `either` or `oneOf`,
  such as the tagged forms of `types.expression`. It does not look inside
  a list's element type, so `expression`'s bare-list branch adds nothing.
*/
let
  tagsOf =
    type:
    if type.functor.payload ? tags then
      builtins.attrNames type.functor.payload.tags
    else if type.nestedTypes ? left then
      tagsOf type.nestedTypes.left ++ tagsOf type.nestedTypes.right
    else
      [ ];
in
tagsOf
