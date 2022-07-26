<?php

declare(strict_types=1);

namespace Jose\Component\KeyManagement\Analyzer;

use function is_string;
use Jose\Component\Core\JWK;
use ParagonIE\ConstantTime\Base64UrlSafe;

final class OctAnalyzer implements KeyAnalyzer
{
    public function analyze(JWK $jwk, MessageBag $bag): void
    {
        if ($jwk->get('kty') !== 'oct') {
            return;
        }
        $k = $jwk->get('k');
        if (! is_string($k)) {
            $bag->add(Message::high('The key is not valid'));

            return;
        }
        $k = Base64UrlSafe::decode($k);
        $kLength = 8 * mb_strlen($k, '8bit');
        if ($kLength < 128) {
            $bag->add(Message::high('The key length is less than 128 bits.'));
        }
    }
}
