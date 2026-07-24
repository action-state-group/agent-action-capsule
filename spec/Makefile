# SPDX-License-Identifier: BSD-3-Clause
# Build the Internet-Draft from the kramdown-rfc source.
#
# kramdown-rfc emits RFCXML v2, so the build converts v2 -> v3 with
# `xml2rfc --v2v3` before rendering text.
#
# Toolchain (one-time):
#   gem install kramdown-rfc
#   python3 -m venv ~/.venvs/x2r && ~/.venvs/x2r/bin/pip install xml2rfc

DRAFT    = draft-mih-scitt-agent-action-capsule-04
# NOTE: this draft is NOT covered by the spec staleness gate, which follows
# DRAFT above.  It cannot be, yet: a rebuild of -02 today renders
# I-D.mih-agent-reputation-predicates as "*** BROKEN REFERENCE ***" because
# that draft no longer resolves (datatracker doc page and bibxml3 endpoint both
# return 404), while the committed .txt still carries the fully rendered
# citation.  All three revisions -00/-01/-02 cite it.  Gating this draft before
# that is resolved would simply land a red gate.
BILATERAL = draft-mih-agent-bilateral-attestation-02
CPB      = draft-mih-sokolov-scitt-payload-binding-00
XML2RFC  ?= ~/.venvs/x2r/bin/xml2rfc
KDRFC    ?= kramdown-rfc

.PHONY: all bilateral cpb clean idnits rebuild refresh-refs

all: $(DRAFT).xml $(DRAFT).txt

# Force a rebuild from the Markdown source.
#
# `make` decides by modification time, and several routine git operations give a
# generated file a *fresh* mtime without changing its contents -- a fresh clone,
# a checkout, or resolving a conflict with `git checkout --ours`.  When that
# happens make judges the .xml newer than the .md, skips kramdown entirely, and
# regenerates only the .txt from the stale .xml.  The output says "Created file"
# and looks like a successful build while shipping the previous revision's text.
# Use this target after any merge or checkout; never restore a generated file
# from a branch and trust a plain `make`.
rebuild:
	rm -f $(DRAFT).xml $(DRAFT).txt
	$(MAKE) all

# Re-fetch the bibliographic reference cache.
#
# .refcache/ is COMMITTED so that building the draft never depends on
# bib.ietf.org being reachable.  Every uncached build fetches one file per
# external reference, so an outage at the IETF reds the spec gate on every open
# pull request simultaneously, for reasons unrelated to any of them.
#
# RFC references are immutable and need no refreshing.  References to
# Internet-Drafts are not -- and this draft cites several of them WITHOUT a
# version pin, so they resolve to whatever revision is current at fetch time.
# Run this before submitting a revision so a superseded I-D reference cannot be
# carried forward silently, and rebuild afterwards so the artifacts agree with
# the cache.
refresh-refs:
	rm -rf .refcache
	$(KDRFC) $(DRAFT).md > /dev/null
	@echo "refreshed: $$(ls .refcache | wc -l) references -- review 'git diff' before committing"

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
