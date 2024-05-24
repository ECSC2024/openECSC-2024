<?php

include 'classes/autoload.php';

UserSession::destroySession();
header( 'Location: /' );
