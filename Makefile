# Звіти лабораторних робіт.
#   make            зібрати всі звіти (PDF)
#   make L=01       лише Labs/01-*/
#   make run        перерахувати solution.py (графіки йдуть у Labs/NN-*/assets)
#   make check      перевірити верстку звітів (Overfull \vbox) і відсутність тире
#   make clean      видалити зібране (Labs/*/out)
#
# Звіт: Labs/NN-*/report.md -> pandoc + xelatex з templates/kpi.latex (титулка
# КПІ). Імена як у суміжних курсах: <тип><№>_<тема>_<прізвище>_<група>, лише ASCII.

PANDOC  ?= pandoc
ENGINE  ?= xelatex
PY      ?= .venv/bin/python
TEMPLATE := templates/kpi.latex
HIGHLIGHT := $(if $(shell kpsewhich framed.sty),--highlight-style=tango,--no-highlight)

NAME_01 := RiskDynamics
NAME_02 := CVSS
NAME_03 := Cooja
NAME_04 := CoojaAttack
NAME_05 := ModbusTLS
SUFFIX  := Vovkotrub_FB-61mn

LABS := $(if $(L),$(wildcard Labs/$(L)-*/),$(wildcard Labs/[0-9]*/))
labnum = $(word 1,$(subst -, ,$(notdir $(patsubst %/,%,$(1)))))
report_pdf = $(1)out/LR$(patsubst 0%,%,$(call labnum,$(1)))_$(NAME_$(call labnum,$(1)))_$(SUFFIX).pdf

REPORTS := $(foreach d,$(LABS),$(if $(wildcard $(d)report.md),$(call report_pdf,$(d))))
SCRIPTS := $(foreach d,$(LABS),$(wildcard $(d)solution.py))

.PHONY: all reports run check dashes clean
all: reports
reports: $(REPORTS)

.SECONDEXPANSION:
$(REPORTS): $$(patsubst %/out/,%/report.md,$$(dir $$@)) $(TEMPLATE) $$(wildcard $$(dir $$@)../assets/*)
	@mkdir -p $(dir $@)
	$(PANDOC) $< -o $@ \
	    --template=$(TEMPLATE) \
	    --pdf-engine=$(ENGINE) \
	    --resource-path=$(dir $<):$(dir $<)assets \
	    $(HIGHLIGHT) \
	    --number-sections \
	    --toc

run:
	@for s in $(SCRIPTS); do \
	    d=$$(dirname $$s); echo "== $$s"; \
	    (cd $$d && $(CURDIR)/$(PY) solution.py) || exit 1; \
	done

# Pandoc ковтає лог xelatex, тож переповнення сторінки не видно, а через нього
# LaTeX мовчки викидає текст. Звіт не готовий, поки тут не vbox=0.
check: dashes
	@fail=0; \
	for d in $(LABS); do \
	  [ -f "$$d/report.md" ] || continue; \
	  tmp=$$(mktemp -d); \
	  $(PANDOC) "$$d/report.md" -o $$tmp/r.tex --template=$(TEMPLATE) \
	      --number-sections --toc --standalone 2>/dev/null; \
	  (TEXINPUTS=$$PWD/$$d:$$PWD/$${d}assets: xelatex -interaction=nonstopmode \
	      -output-directory=$$tmp $$tmp/r.tex >$$tmp/log 2>&1); \
	  vb=$$(grep -c 'Overfull .vbox' $$tmp/log || true); \
	  hb=$$(grep -c 'Overfull .hbox' $$tmp/log || true); \
	  if [ "$$vb" -gt 0 ]; then printf "  %s: vbox=%s hbox=%s  <- ВТРАТА ТЕКСТУ\n" "$$d" "$$vb" "$$hb"; fail=1; \
	  else printf "  %s: vbox=0 hbox=%s\n" "$$d" "$$hb"; fi; \
	  rm -rf $$tmp; \
	done; \
	[ $$fail -eq 0 ] && echo "верстка чиста" || { echo "є переповнення сторінки"; exit 1; }

# Без довгих і середніх тире в текстах звітів.
dashes:
	@if grep -n '[—–]' $(foreach d,$(LABS),$(wildcard $(d)report.md)) /dev/null; then \
	  echo "знайдено тире (— або –): замініть"; exit 1; else echo "тире немає"; fi

clean:
	rm -rf Labs/*/out
