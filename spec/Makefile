# SPDX-License-Identifier: BSD-3-Clause
# Build the Internet-Draft from the kramdown-rfc source.
#
# kramdown-rfc emits RFCXML v2; the committed .xml MUST be RFCXML v3 (RFC 7991),
# so the build converts v2 -> v3 with `xml2rfc --v2v3` before rendering text.
#
# Toolchain (one-time):
#   gem install kramdown-rfc
#   python3 -m venv ~/.venvs/x2r && ~/.venvs/x2r/bin/pip install xml2rfc

DRAFT    = draft-mih-scitt-agent-action-capsule-00
BILATERAL = draft-mih-agent-bilateral-attestation-00
CPB      = draft-mih-sokolov-scitt-payload-binding-00
XML2RFC  ?= ~/.venvs/x2r/bin/xml2rfc
KDRFC    ?= kramdown-rfc

.PHONY: all bilateral cpb clean idnits

all: $(DRAFT).xml $(DRAFT).txt

bilateral: $(BILATERAL).xml $(BILATERAL).txt

cpb: $(CPB).xml $(CPB).txt

# md -> v2 xml -> v3 xml (committed artifact is v3)
$(DRAFT).xml: $(DRAFT).md
	$(KDRFC) $(DRAFT).md > .$(DRAFT).v2.xml
	$(XML2RFC) --v2v3 .$(DRAFT).v2.xml -o $(DRAFT).xml
	@rm -f .$(DRAFT).v2.xml

$(BILATERAL).xml: $(BILATERAL).md
	$(KDRFC) $(BILATERAL).md > .$(BILATERAL).v2.xml
	$(XML2RFC) --v2v3 .$(BILATERAL).v2.xml -o $(BILATERAL).xml
	@rm -f .$(BILATERAL).v2.xml

$(CPB).xml: $(CPB).md
	$(KDRFC) $(CPB).md > .$(CPB).v2.xml
	$(XML2RFC) --v2v3 .$(CPB).v2.xml -o $(CPB).xml
	@rm -f .$(CPB).v2.xml

# v3 xml -> text
$(DRAFT).txt: $(DRAFT).xml
	$(XML2RFC) --text --v3 $(DRAFT).xml -o $(DRAFT).txt

$(BILATERAL).txt: $(BILATERAL).xml
	$(XML2RFC) --text --v3 $(BILATERAL).xml -o $(BILATERAL).txt

$(CPB).txt: $(CPB).xml
	$(XML2RFC) --text --v3 $(CPB).xml -o $(CPB).txt

idnits: $(DRAFT).txt
	npx --yes @ietf-tools/idnits $(DRAFT).txt

clean:
	rm -f .$(DRAFT).v2.xml .$(BILATERAL).v2.xml .$(CPB).v2.xml
