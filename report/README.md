# Build

Requires a LaTeX distribution with TikZ (MiKTeX or TeX Live).

```
pdflatex main
pdflatex main   # twice, so the ToC, LoF, LoT and cross-references resolve
```

Output: main.pdf (76 pages).

## Files

| File | Contents |
|---|---|
| main.tex | Preamble, packages, TikZ styles, chapter includes |
| frontmatter.tex | Title page, certificate, declaration, abstract, acknowledgement, ToC |
| ch1_introduction.tex | Problem statement, base paper, objectives |
| ch2_preliminaries.tex | Hashes, ECC, ECDH, nonces, Dolev-Yao, notation |
| ch3_baseprotocol.tex | Network model, three phases, M1-M12, worked example, fallback |
| ch4_basesecurity.tex | BAN logic, propositions, Scyther, performance tables |
| ch5_implementation.tex | Our simulator and the defects in its first version |
| ch6_improvements.tex | The seven enhancements, AES-GCM first |
| ch7_scyther.tex | SPDL model, restructuring, 32/32 claims |
| ch8_results.tex | The seven generated plots and measured results |
| ch9_conclusion.tex | Deviations, limitations, future work, conclusion |
| bibliography.tex | 17 references |
| figures/ | Plots copied from ../output/ |
