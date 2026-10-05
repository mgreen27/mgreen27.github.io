---
areas: ["AI"]
layout: post
title: "AI Ate My DFIR Homework"
date: 2026-06-24
draft: true
tags: [DFIR,AI,Velociraptor]
showTags: true
summary: Notes from research into automated AI-assisted DFIR analysis, including Velociraptor workflows, repeatable analysis skills, and where human judgement still matters.
---

I have been spending time researching how AI can help with DFIR analysis without turning the whole process into a magic black box. The short version is: AI can eat some of the homework, but it still needs a good analyst setting the task, checking the reasoning, and deciding what matters.

This post is a starting point for sharing that work. I will be releasing some AI skills and talking through the analysis patterns behind them: what worked, what failed, and where automation actually made investigations faster.

## Why This Matters

DFIR work often involves a lot of repetitive interpretation:

- reviewing endpoint collections
- summarising suspicious process activity
- pulling signal out of noisy event logs
- comparing artifacts across hosts
- turning notebook output into investigation notes
- deciding what to inspect next

None of those tasks disappear just because AI is in the loop. The question I am interested in is more practical: can we give an analyst a reliable assistant that handles the first pass, preserves evidence, explains its reasoning, and makes the next decision easier?

That is the area I have been testing.

## Where Velociraptor Fits

Velociraptor is a great place to explore this because it already gives us structured, repeatable collection and analysis. VQL notebooks, artifacts, hunts, and offline collections all provide data with enough shape that an AI workflow can reason over it more safely than a raw pile of logs.

The pattern I keep coming back to is:

1. collect the right data with Velociraptor
2. reduce it into a useful analysis view
3. ask AI to explain, cluster, enrich, or prioritise the results
4. keep the analyst in control of the conclusion

In other words, I am not trying to replace the DFIR workflow. I am trying to make the boring parts less boring and the important parts easier to see.

## Skills, Not Spells

One of the traps with AI tooling is pretending that a single prompt can do everything. In practice, the useful work comes from narrower skills that know their job.

For DFIR, that might mean skills that can:

- summarise a Velociraptor collection
- review process execution for suspicious chains
- explain a VQL notebook result
- triage persistence artifacts
- generate investigation notes from evidence
- identify gaps in the collection
- suggest follow-up Velociraptor artifacts to run

The skill needs to be small enough to test, repeat, and improve. If it cannot explain how it got to an answer, it is probably not ready for incident response.

## What I Am Looking For

The research so far has focused on a few practical questions:

- How much context does the AI need before it starts making useful observations?
- Which DFIR tasks are safe to automate, and which should only be assisted?
- How do we keep citations back to evidence instead of producing unsupported summaries?
- Can we make Velociraptor output easier to review without hiding the raw data?
- What does a good handoff between AI and analyst look like?

The answer is not "just add AI." The better answer is careful workflow design: structured inputs, constrained tasks, visible reasoning, and fast validation.

## Next Steps

I will be sharing some of the AI skills I have been building and using this blog to talk through the analysis behind them. Expect a mix of Velociraptor, DFIR workflow notes, and practical examples from automated analysis experiments.

AI did not really eat my DFIR homework. But it might help sort the pile, highlight the weird bits, and leave me more time to do the actual investigation.
