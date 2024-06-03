<?php

function available_languages()
{
	// list files in the i18n directory
	$files = scandir(__DIR__ . '/i18n');
	$languages = [];
	foreach ($files as $file) {
		if (is_file(__DIR__ . '/i18n/' . $file)) {
			$languages[] = explode('.', $file)[0];
		}
	}
	return $languages;
}

function get_language()
{
	if (isset($_COOKIE['lang'])) {
		$lang = $_COOKIE['lang'];
	} else {
		$lang = explode('-', explode(';', $_SERVER['HTTP_ACCEPT_LANGUAGE'])[0])[0];
	}

	if (!in_array($lang, available_languages())) {
		$lang = 'en';
	}
	return $lang;
}

function t($key)
{
	if (!isset($GLOBALS['lang_data'])) {
		$lang = get_language();
		$GLOBALS['lang_data'] = json_decode(file_get_contents(__DIR__ . '/i18n/' . $lang . '.json'), true);
	}
	$data = $GLOBALS['lang_data'];

	$fragments = explode('.', $key);

	foreach ($fragments as $fragment) {
		if (!isset($data[$fragment])) {
			return $key;
		}
		$data = $data[$fragment];
	}

	return $data;
}

function get_flag_icon($lang)
{
	if ($lang == 'en') {
		return '<svg xmlns="http://www.w3.org/2000/svg" id="flag-icons-gb" viewBox="0 0 640 480">
					<path fill="#012169" d="M0 0h640v480H0z" />
					<path fill="#FFF" d="m75 0 244 181L562 0h78v62L400 241l240 178v61h-80L320 301 81 480H0v-60l239-178L0 64V0z" />
					<path fill="#C8102E" d="m424 281 216 159v40L369 281zm-184 20 6 35L54 480H0zM640 0v3L391 191l2-44L590 0zM0 0l239 176h-60L0 42z" />
					<path fill="#FFF" d="M241 0v480h160V0zM0 160v160h640V160z" />
					<path fill="#C8102E" d="M0 193v96h640v-96zM273 0v480h96V0z" />
				</svg>';
	}
	if ($lang == 'it') {
		return '<svg xmlns="http://www.w3.org/2000/svg" id="flag-icons-it" viewBox="0 0 640 480">
					<g fill-rule="evenodd" stroke-width="1pt">
						<path fill="#fff" d="M0 0h640v480H0z" />
						<path fill="#009246" d="M0 0h213.3v480H0z" />
						<path fill="#ce2b37" d="M426.7 0H640v480H426.7z" />
					</g>
				</svg>';
	}
	if ($lang == 'fr') {
		return '<svg xmlns="http://www.w3.org/2000/svg" id="flag-icons-fr" viewBox="0 0 640 480">
					<path fill="#fff" d="M0 0h640v480H0z" />
					<path fill="#000091" d="M0 0h213.3v480H0z" />
					<path fill="#e1000f" d="M426.7 0H640v480H426.7z" />
				</svg>';
	}
	if ($lang == 'ge') {
		return '<svg xmlns="http://www.w3.org/2000/svg" id="flag-icons-gb-eng" viewBox="0 0 640 480">
					<path fill="#fff" d="M0 0h640v480H0z" />
					<path fill="#ce1124" d="M281.6 0h76.8v480h-76.8z" />
					<path fill="#ce1124" d="M0 201.6h640v76.8H0z" />
				</svg>';
	}
	if ($lang == 'de') {
		return '<svg xmlns="http://www.w3.org/2000/svg" id="flag-icons-de" viewBox="0 0 640 480">
					<path fill="#fc0" d="M0 320h640v160H0z"/>
					<path fill="#000001" d="M0 0h640v160H0z"/>
					<path fill="red" d="M0 160h640v160H0z"/>
				</svg>';
	}
}
