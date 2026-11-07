# Limitations

toledot is honest about what it cannot do. This page grows as features are built.

## Out of scope

The tool will not:

- Monitor or alert in real time.
- Collect events from domain controllers in the first release. Inputs are exported files.
- Judge whether a change was authorized.

## Limits of any file-based check

- The tool sees only what the inputs contain. It cannot detect records a source system did not export.
- A clean result means no findings in the supplied inputs. It is not proof that the environment is correct.
- Results are only as current as the inputs. Reports show capture times when the inputs provide them.
