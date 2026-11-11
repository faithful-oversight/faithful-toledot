# Examples

## corp-example

`corp-example` is a synthetic example. It describes a made-up domain, `corp.example`, with two domain controllers, `DC01.corp.example` and `DC02.corp.example`. The domain SID, account names, addresses, and every other identifier are invented. Addresses come from the ranges reserved for documentation. No real organization's data is here.

| File | What it is |
| --- | --- |
| `dc01-events.jsonl` | A collection file as the PowerShell collector writes it on DC01: one week of the Security log. |
| `dc02-events.jsonl` | A collection file as the PowerShell collector writes it on DC02. |
| `sample-report/` | The reports `toledot report` writes for both files. |

The week includes ordinary account and group administration, two directory changes, and an audit policy change. It also includes the things the report must explain, so they all appear in it:

- An administrator cleared the Security log on DC02. This makes the account incomplete.
- DC02's log had already overwritten its oldest events when it was collected, so earlier events are missing. This also makes the account incomplete.
- 412 record numbers are absent from DC01's log. The collector asked only for the events toledot reads, so this gap is expected, and the report explains why it does not count against completeness.

Open `sample-report/toledot-report.html` in a browser to see the report. The report files are `toledot-report.html`, `toledot-report.md`, `toledot-report.json`, `toledot-changes.csv`, and `toledot-manifest.json`.

### Regenerate the sample

The collection files come from `toledot example`. The reports come from this command, run from the repository root. `SOURCE_DATE_EPOCH` fixes the generation time, so the same code always writes the same bytes:

```shell
toledot example examples/corp-example --force
SOURCE_DATE_EPOCH=1794225600 toledot report examples/corp-example/dc01-events.jsonl examples/corp-example/dc02-events.jsonl -o examples/corp-example/sample-report --force
```

toledot exits with code `1` because the account is incomplete. A test checks that the committed files match what the current code writes, apart from the tool version.

### Try it yourself

```shell
toledot example ./toledot-demo
toledot report ./toledot-demo/dc01-events.jsonl ./toledot-demo/dc02-events.jsonl -o ./toledot-demo/report
```
