<!DOCTYPE html>
<html>

<head>
    <title>Past(a)man</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            text-align: center;
        }

        h1 {
            color: #333;
        }

        form {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 5px;
        }

        input[type="text"],
        select,
        textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
        }

        input[type="submit"] {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }

        input[type="submit"]:hover {
            background-color: #45a049;
        }

        #responsediv {
            margin-top: 20px;
            border: 1px solid #ccc;
            padding: 10px;
            background-color: #f9f9f9;
            text-align: left;
        }

        .flex-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .flex-container>* {
            flex: 1;
        }

        input[type="submit"] {
            width: 100%;
            margin-top: 10px;
        }

        #addHeaderButton {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            padding: 5px 10px;
            margin-left: 5px;
            text-align: center;
            text-decoration: none;
            font-weight: bold;
            border-radius: 4px;
            cursor: pointer;
        }

        #addHeaderButton:hover {
            background-color: #45a049;
        }

        label {
            margin-bottom: 10px;
            margin-top: 18px;
        }

        .removeHeader {
            display: inline-flex;
            justify-content: center;
            align-items: center;
            width: 33px;
            height: 33px;
            background-color: #f44336;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-left: 5px;
            flex: none;
        }

        .removeHeader:hover {
            background-color: #d32f2f;
        }

        #samplereq button {
            background-color: #008CBA;
            border: none;
            color: white;
            padding: 10px 20px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            margin: 4px 2px;
            cursor: pointer;
            border-radius: 12px;
            transition-duration: 0.4s;
        }

        #samplereq button:hover {
            background-color: #00688B;
        }
    </style>

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/default.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>

</head>

<body>
    <div id="samplereq"></div>
    <h1>Request</h1>
    <form method="post">
        <div class="flex-container">
            <select name="method" id="method" style="flex: none; width: 100px; margin-right: 5px" required>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
            </select>
            <input type="text" name="path" id="path" placeholder="Path" value="/" required>
        </div>
        <label for="headers">Headers <div id="addHeaderButton">+</div></label>
        <div id="headers">
            <div id="headerDefault" class="flex-container">
                <input type="text" value="Content-Type: application/json">
                <div class="removeHeader" id="removeHeaderDefault">-</div>
            </div>
        </div>
        <label for="body">Body</label>
        <textarea name="body" id="body" rows="5"></textarea>
        <input type="submit" value="Send Request">
    </form>

    <div id="responsecontainer" style="display: none;">
        <br>
        <hr>
        <h2>Response</h2>
        <div id="responsediv">
            <pre><code id="response" class="language-json"></code></pre>
        </div>

    </div>

    <script>
        const recipes = [
            '"name": "Spaghetti Carbonara", "description": "Pasta with eggs, cheese, pancetta, and black pepper"',
            '"name": "Spaghetti Bolognese", "description": "Pasta with a meat sauce"',
            '"name": "Lasagna", "description": "Pasta with layers of meat sauce and cheese"',
            '"name": "Pasta al Pesto", "description": "Pasta with a sauce made of basil, garlic, pine nuts, and cheese"',
            '"name": "Pasta all\'Amatriciana", "description": "Pasta with a sauce made of tomatoes, pancetta, and pecorino cheese"',
            '"name": "Pasta alla Norma", "description": "Pasta with a sauce made of tomatoes, eggplant, and ricotta salata cheese"',
            '"name": "Pasta alla Puttanesca", "description": "Pasta with a sauce made of tomatoes, olives, capers, and garlic"',
            '"name": "Pasta alla Carbonara", "description": "Pasta with eggs, cheese, pancetta, and black pepper"',
            '"name": "Pasta alla Gricia", "description": "Pasta with cheese, pancetta, and black pepper"',
            '"name": "Pasta alla Maruzzara", "description": "Pasta with a sauce made of tomatoes, garlic, and parsley"',
            '"name": "Pasta alla Sorrentina", "description": "Pasta with a sauce made of tomatoes, mozzarella, and basil"',
            '"name": "Pasta alla Siciliana", "description": "Pasta with a sauce made of tomatoes, eggplant, and ricotta salata cheese"',
            '"name": "Pasta alla Trapanese", "description": "Pasta with a sauce made of tomatoes, almonds, and garlic"',
            '"name": "Pasta alla Zozzona", "description": "Pasta with a sauce made of tomatoes, pancetta, and pecorino cheese"',
        ]

        const sampleRequests = [{
                name: 'Ping',
                method: 'GET',
                path: '/ping',
                body: '',
            },
            {
                name: 'Register',
                method: 'POST',
                path: '/register',
                body: '{"username": "' + Math.random().toString(36).substring(2, 10) + '"}',

            },
            {
                name: 'Hello',
                method: 'GET',
                path: '/hello',
                body: '',
            },
            {
                name: 'List recipes',
                method: 'GET',
                path: '/recipes',
                body: '',
            },
            {
                name: 'Create recipe',
                method: 'POST',
                path: '/recipes',
                body: '{PLACEHOLDER_RECIPE}',
            },
            {
                name: 'Update recipe',
                method: 'PUT',
                path: '/recipes',
                body: '{"id": 0, PLACEHOLDER_RECIPE}',
            },
            {
                name: 'Delete recipe',
                method: 'DELETE',
                path: '/recipes',
                body: '{"id": 0}',
            },
            {
                name: 'Feeling lucky?',
                method: 'POST',
                path: '/flag',
                body: '{"guess": "' + '0'.repeat(20) + '"}',
            }
        ];

        const sampleReqDiv = document.getElementById('samplereq');
        sampleRequests.forEach((req) => {
            const button = document.createElement('button');
            button.textContent = req.name;
            button.addEventListener('click', () => {
                document.getElementById('method').value = req.method;
                document.getElementById('path').value = req.path;
                document.getElementById('body').value = req.body.replace('PLACEHOLDER_RECIPE', recipes[Math.floor(Math.random() * recipes.length)]);
            });
            sampleReqDiv.appendChild(button);
        });


        const form = document.querySelector('form');
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            document.getElementById('responsecontainer').style.display = 'none';

            const path = form.querySelector('#path').value;
            const method = form.querySelector('#method').value;
            const body = form.querySelector('#body').value;

            const params = new URLSearchParams({
                path,
                method,
                body,
            });

            form.querySelector('#headers').querySelectorAll('input').forEach((input) => {
                params.append('headers[]', input.value);
            });

            const responseCode = document.querySelector('#response');

            const response = await fetch('/request.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: params,
            });

            const text = await response.text();

            try {
                const json = JSON.parse(text);
                responseCode.innerHTML = hljs.highlight(JSON.stringify(json, null, 4), {
                    language: 'json'
                }).value;
            } catch (e) {
                responseCode.innerHTML = hljs.highlight(text, {
                    language: 'html'
                }).value;
            }
            document.getElementById('responsecontainer').style.display = 'block';
        });

        document.getElementById('addHeaderButton').addEventListener('click', function() {
            const headersDiv = document.getElementById('headers');

            const flexContainer = document.createElement('div');
            flexContainer.className = 'flex-container';

            const newHeaderInput = document.createElement('input');
            newHeaderInput.type = 'text';
            flexContainer.appendChild(newHeaderInput);

            // Create new remove button for header
            const removeButton = document.createElement('div');
            removeButton.className = 'removeHeader';
            removeButton.textContent = '-';
            removeButton.addEventListener('click', function() {
                headersDiv.removeChild(flexContainer);
            });
            flexContainer.appendChild(removeButton);

            headersDiv.appendChild(flexContainer);
        });

        document.getElementById('removeHeaderDefault').addEventListener('click', function() {
            document.getElementById('headers').removeChild(document.getElementById('headerDefault'));
        });
    </script>
</body>

</html>