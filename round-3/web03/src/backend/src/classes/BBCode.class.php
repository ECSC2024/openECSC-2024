<?php


class BBCode {

	public static $bbcodes_regex = [ 
		'\[url\]', '\[img\]', '\[url\=.+\]', '\[math\]', '\[i\]', '\[b\]', '\[u\]', '\[hr\]', '\[size\=.+\]', '\[quote\]', '\[note\]', '\[quote\=.+\]','\[list\]', '\[\*\]',
		'\[/url\]', '\[/img\]', '\[/math\]', '\[/i\]', '\[/b\]', '\[/u\]', '\[hr\]', '\[/size\]', '\[/quote\]', '\[/note\]', '\[/list\]'
	];

	public static function check_url( $url ) {
		if ( str_starts_with( $url, '//' ) ) {
			$url = 'https:' . $url;
		}
		;

		return ( str_starts_with( $url, 'http://' ) || str_starts_with( $url, 'https://' ) ) &&
			filter_var( $url, FILTER_VALIDATE_URL ) !== false;
	}

	public static function convert_url( $m ) {
		$m[1] = trim( $m[1] );
		if ( ! self::check_url( $m[1] ) ) {
			$m[1] = 'http://' . $m[1];
			if ( ! self::check_url( $m[1] ) ) {
				return '<b>INVALID URL</b>';
			}
		}
		$url = $m[1];
		$url_info = parse_url( $url );
		if ( ! $url_info ) {
			return '<b>INVALID URL</b>';
		}
		$url = static::stripBBCodeTags( $url );

		return isset( $m[2] )
			? '<a href="' . $url . '">' . $m[2] . '</a>'
			: '<a href="' . $url . '">' . $m[1] . '</a>';
	}

	public static function convert_img( $m ) {
		$m[1] = trim( $m[1] );
		if ( ! self::check_url( $m[1] ) ) {
			$m[1] = 'http://' . $m[1];
			if ( ! self::check_url( $m[1] ) ) {
				return '<b>INVALID URL</b>';
			}
		}
		$url = $m[1];
		$url_info = parse_url( $url );
		if ( ! $url_info ) {
			return '<b>INVALID URL</b>';
		}
		$url = static::stripBBCodeTags( $url );

		return '<img src="' . $url . '">';
	}

	public static function stripBBCodeTags( $s ) {
		foreach ( static::$bbcodes_regex as $bbcode ) {
			$s = preg_replace( '#' . $bbcode . '#Ui', '', $s );
		}
		return $s;

	}
	public static function parse( $str ) {

		$code_n = 0;
		$code_s = [];
		$str = preg_replace_callback( '#\[code\](.*)\[/code\]#Ui', function ($m) use (&$code_n, &$code_s) {
			array_push( $code_s, $m[1] );
			return ">>>" . $code_n++ . "<<<";
		}, $str );

		$str = preg_replace_callback( '#\[url=(.+)\](.+?)\[/url\]#Ui', function ($m) {
			return static::convert_url( $m );
		}, $str );
		$str = preg_replace_callback( '#\[url](.+)\[/url\]#Ui', function ($m) {
			return static::convert_url( $m );
		}, $str );
		$str = preg_replace_callback( '#\[img\](.+)\[/img\]#Ui', function ($m) {
			return static::convert_img( $m );
		}, $str );

		$str = preg_replace( '#\[i\](.+)\[/i\]#Ui', '<span class="font-italic">$1</span>', $str );
		$str = preg_replace( '#\[b\](.+)\[/b\]#Ui', '<span class="font-weight-bold">$1</span>', $str );
		$str = preg_replace( '#\[u\](.+)\[/u\]#Ui', '<u>$1</u>', $str );
		$str = preg_replace( '#\[hr\]#i', '<hr/>', $str );
		$str = preg_replace( '#\[size\=([0-9]+)\](.+)\[size\]#Ui', '<span style="$1">$2</span>', $str );

		$regex = array(
			'#\[list\](.+)\[\/list\]#Uis' => '<ul>$1</ul>',
			'#\[\*\](.+)$#Uim' => '<li>$1</li>'
		);
	
		$str = preg_replace(array_keys($regex), array_values($regex), $str);

		$str = preg_replace_callback( "#\[math\](.+)\[/math\]#Ui", function ($m) {
			return '[math]' . strip_tags( $m[1] ) . '[/math]';
		}, $str );


		while ( preg_match( '#\[quote\](.+)\[/quote\]#i', $str ) ) {
			$str = preg_replace(
				'#\[quote\](.+)\[/quote]#i',
				'<blockquote class="blockquote"><p class="mb-0">$1</p></blockquote>',
				$str,
				1
			);
		}

		while ( preg_match( '#\[quote=(.+)\](.+)\[/quote\]#i', $str ) ) {
			$str = preg_replace_callback( '#\[quote=(.+)\](.+)\[/quote]#i', function ($m) {
				$author = $m[1];
				$author = filter_var( $author, FILTER_SANITIZE_ENCODED );
				return '<blockquote class="blockquote"><p class="mb-0"> ' . $m[2] . '</p>
				<footer class="blockquote-footer"><cite title="' . $m[1] . '">Source Title</cite></footer>
			  </blockquote>';
			},
				$str,
				1
			);
		}
		$str = preg_replace_callback( '#\[note\=(.+)\](.+)\[/note\]#i', function ($m) {
			$id = $m[1];
			$caption = $m[2];

			$id = filter_var( $id, FILTER_SANITIZE_ENCODED );

			return '<a href="/view.php?id=' . $id . '">' . $caption . '</a>';
		}, $str );
		$str = str_replace( "\n", '<br>', $str );
		while ( $code_n > 0 ) {
			--$code_n;
			$str = str_ireplace( ">>>{$code_n}<<<", '<code>' . $code_s[ $code_n ] . '</code>', $str );
		}

		return $str;
	}

}