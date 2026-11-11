# toledot documentation

toledot reads Windows event logs from an Active Directory domain controller and writes a plain-English account of who changed what, from where, and when. It says what the logs cannot show, and it never claims more than the evidence supports.

## Start here

- [Quickstart](quickstart.md): install toledot and run the synthetic example in five minutes.
- [Collecting events](collecting.md): run the collector on a domain controller, or collect remotely.
- [Command reference](usage.md): every command, option, and exit code, plus pipeline examples.
- [Input formats](formats.md): the formats toledot reads and the collection file.
- [Reports and results](output.md): the report sections, completeness levels, and output formats.
- [Limitations](limitations.md): what toledot cannot do.

## Design

- [Architecture](architecture.md): how the tool is built and the rules the design follows.
- [Threat model](threat-model.md): what the tool protects, the threats, and the controls.
- [Releasing](releasing.md): how releases are made and verified.
- [Architecture decision records](adr/index.md): significant decisions and the reasons for them.
