<!DOCTYPE html>
<html lang="en">

<head>
    <title>Just another useless website</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body>
    <div style="display: contents">

        <section class="bg-gray-50 g-gray-900 min-h-screen flex flex-col justify-between">
            <nav class="bg-white border-gray-200 order-gray-600 g-gray-900 border-y">
                <div class="flex flex-wrap justify-between items-center mx-auto max-w-screen-xl p-4">
                    <a href="/" class="flex items-center space-x-3 rtl:space-x-reverse">
                        <span class="self-center text-2xl font-semibold whitespace-nowrap ext-white">Just another useless website</span>
                    </a>
                    <div id="mega-menu-full" class="hidden items-center justify-between font-medium w-full md:flex md:w-auto md:order-1">
                        <ul class="flex flex-col p-4 md:p-0 mt-4 border border-gray-100 rounded-lg bg-gray-50 md:space-x-8 rtl:space-x-reverse md:flex-row md:mt-0 md:border-0 md:bg-white g-gray-800 md:g-gray-900 order-gray-700">
                            <li>
                                <a href="/" class="block py-2 px-3 text-gray-900 rounded hover:bg-gray-100 md:hover:bg-transparent md:hover:text-blue-700 md:p-0 ext-white md:over:text-blue-500 over:bg-gray-700 over:text-blue-500 md:over:bg-transparent order-gray-700" aria-current="page">Home</a>
                            </li>
                            <?php if ($user == null) { ?>
                                <li>
                                    <a href="/login.php" class="block py-2 px-3 text-gray-900 rounded hover:bg-gray-100 md:hover:bg-transparent md:hover:text-blue-700 md:p-0 ext-white md:over:text-blue-500 over:bg-gray-700 over:text-blue-500 md:over:bg-transparent order-gray-700">Login</a>
                                </li>

                                <li>
                                    <a href="/register.php" class="block py-2 px-3 text-gray-900 rounded hover:bg-gray-100 md:hover:bg-transparent md:hover:text-blue-700 md:p-0 ext-white md:over:text-blue-500 over:bg-gray-700 over:text-blue-500 md:over:bg-transparent order-gray-700">Register</a>
                                </li>
                            <?php } else { ?>
                                <li>
                                    <a href="/logout.php" class="block py-2 px-3 text-gray-900 rounded hover:bg-gray-100 md:hover:bg-transparent md:hover:text-blue-700 md:p-0 ext-white md:over:text-blue-500 over:bg-gray-700 over:text-blue-500 md:over:bg-transparent order-gray-700">Logout</a>
                                </li>
                            <?php } ?>
                        </ul>
                    </div>
                </div>
            </nav>