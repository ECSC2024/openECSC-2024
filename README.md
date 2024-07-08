# openECSC 2024 - Challenges

## Description

This repository contains all the source codes of the challenges proposed during the rounds of [openECSC 2024](https://open.ecsc2024.it) and the italian competition mirrors.

[openECSC](https://open.ecsc2024.it) is a cybersecurity competition open to everyone that invites enthusiasts to participate without any kind of limitations. Launched in 2022 as an extension of the European Cybersecurity Challenge, it aims to broaden participation beyond traditional age and nationality restrictions, featuring a series of jeopardy-style CTF competition rounds culminating in a 24-hour final round in 2024.

The 2024 edition of the [openECSC](https://open.ecsc2024.it) competition is organized by the [CINI Cybersecurity National Lab](https://cybersecnatlab.it/) and [Italian National Cybersecurity Agency](https://www.acn.gov.it/portale/en/home) in preparation of the European Cybersecurity Challenge 2024 to be held in Turin from 7th to 11th of October 2024.

## Schedule

| # Round     | Starting time           | Ending time             | Source              |
| :---------- | :---------------------- | :---------------------- | :------------------ |
| Round 1     | 18 Mar. 2024, 10:00 UTC | 24 Mar. 2024, 22:00 UTC | [Round 1](round-1/) |
| Round 2     | 22 Apr. 2024, 10:00 UTC | 28 Apr. 2024, 22:00 UTC | [Round 2](round-2/) |
| Round 3     | 13 May 2024, 10:00 UTC  | 19 May 2024, 22:00 UTC  | [Round 3](round-3/) |
| Final Round | 21 Set. 2024, 10:00 UTC | 22 Set. 2024, 10:00 UTC |                     |

## Competition mirrors

This repo will contains also the source codes of the mirror competitions hosted in the [external openECSC platform](https://external.open.ecsc2024.it/) for all the jeopardy-style CTFs organized by the CINI Cybersecurity National Lab.

Be aware that the target audience of these competitions varies a lot and may differs from the openECSC 2024 target, and difficulty levels will be very different among competitions. Descriptions of all the mirrored events are summarized below:

- OliCyber.IT - Regional CTF: regional selection of the Italian Olympiads in Cybersecurity. It is an individual, online, 4h long CTF, aimed to select the top 100 high school students in Italy in the age 14-19 for the national finals. Expect introductory challenges aimed to beginners.
- CyberChallenge.IT - University CTF: local selection for the Italian CyberChallenge.IT program. It is an individual, on-site in each university, 7h long CTF, aimed to select the top 6 students in each university, in the age 16-24, to participate as a team in the national finals. Expect introductory to medium-level challenges.
- OliCyber.IT - National Final: national finals of the Italian Olympiads in Cybersecurity. It is an individual, on-site, 7h long CTF, aimed to 14-19 years old high school students. Expect introductory to medium-level challenges.
- TeamItaly - Preselection CTF: initial selection for the 2024 TeamItaly members, that will represent Italy at the ECSC. It is an individual, on-line, 24h long CTF aimed to 14-25 years old. Expect medium to hard-level challenges.

### Mirrors calendar

| # Round                            | Starting time           | Ending time             | Source                                                              |
| :--------------------------------- | :---------------------- | :---------------------- | :------------------------------------------------------------------ |
| OliCyber.IT - Regional CTF         | 06 Apr. 2024, 13:00 UTC | 06 Apr. 2024, 17:00 UTC | [olicyberit-regional-ctf](olicyberit-regional-ctf/)                 |
| CyberChallenge.IT - University CTF | 29 May 2024, 08:00 UTC  | 29 May 2024, 15:00 UTC  | [cyberchallengeit-university-ctf](cyberchallengeit-university-ctf/) |
| OliCyber.IT - National Final       | 08 Jun. 2024, 08:00 UTC | 08 Jun. 2024, 15:00 UTC | [olicyberit-national-final](olicyberit-national-final/)             |
| TeamItaly - Preselection CTF       | 15 Jun. 2024, 12:00 UTC | 16 Jun. 2024, 12:00 UTC | [teamitaly-preselection-ctf](teamitaly-preselection-ctf/)           |

## Challenge structure

- `/authors.txt`: Challenge authors, one per line, in the format `Nome Cognome <@nickname>`
- `/title.txt`: Title of the challenge
- `/description.md`: Public challenge description for the platform
- `/flags.txt`: Challenge flag(s), one per line, use the format `^...$` to define a regex
- `/points.txt`: Challenge score:
  - static: `score` (e.g. `50`)
  - dynamic: `max,min,decay` (e.g. `50,500,10%`)
- `/endpoint.txt`: challenge deployment endpoint, format: `(http|tcp),$HOST,$PORT`
- `/tags.txt`: Comma-separated tags for the challenge on platform, visible to everyone
- `/tags-hidden.txt`: Comma-separated hidden tags for the challenge on platform, visible to admins and supervisors
- `/order.txt`: Order of the challenge on platform
- `/writeup.md`: Private writeup of the challenge
- `/writeup`: Folder for writeup resources (e.g. images)
- `/attachments/*`: File to attach to the platform for players, folders are for dynamic attachments
- `/src/*`: Sources needed to generate/serve the challenge
- `/src/gen.py`: Script for dynamic attachments generation, takes the user id as the only parameter
- `/hints/*`: Files needed for challenge hints
- `/hints/hint{1,2,...}.md`: Challenge hint(s), prefix `_` to ignore hint
- `/solution.*`: Solution(s) for static challenge
- `/checker/*`: Files needed by the checker
- `/checker/__main__.py`: Python checker that prints the flag
- `/timeout.txt`: Execution timeout in seconds for the checker
