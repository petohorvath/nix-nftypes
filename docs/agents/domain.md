# Domain docs

This is a single-context repo:

```
/
├── GLOSSARY.md    # glossary of domain terms
└── docs/adr/      # architecture decision records
```

## Before exploring

Read `GLOSSARY.md`, plus any ADRs in `docs/adr/` about the area you're working in. If a file is missing, carry on without mentioning it. `/domain-modeling` creates these files once terms or decisions are settled.

## While working

- **Use the glossary's terms** in issue titles, proposals, hypotheses and test names. Don't use synonyms that the glossary avoids. If a concept you need is missing, either drop the invented term or note the gap for `/domain-modeling`.
- **Flag ADR conflicts** instead of silently overriding them. For example: _Contradicts ADR-0003 (…), but worth reopening because…_
