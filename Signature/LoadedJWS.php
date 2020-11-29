<?php

namespace Lexik\Bundle\JWTAuthenticationBundle\Signature;

/**
 * Object representation of a JSON Web Signature loaded from an
 * existing JSON Web Token.
 *
 * @author Robin Chalas <robin.chalas@gmail.com>
 */
final class LoadedJWS
{
    /**
     * @var array
     */
    private $header;

    /**
     * @var array
     */
    private $payload;
    
    /**
     * @var int
     */
    private $clockSkew;

    /**
     * @var bool
     */
    private $hasLifetime;

    /**
     * @var bool
     */
    private $isVerified;

    /**
     * @var bool
     */
    private $isValid;

    /**
     * @var bool
     */
    private $isExpired;

    /**
     * @param array $payload
     * @param bool  $isVerified
     * @param bool  $isValid
     * @param bool  $hasLifetime
     * @param int   $clockSkew
     * @param array $header
     */
    public function __construct(array $payload, $isVerified, $isValid, $hasLifetime = true, array $header = [], $clockSkew = 0)
    {
        $this->payload     = $payload;
        $this->header      = $header;
        $this->hasLifetime = $hasLifetime;
        $this->clockSkew   = $clockSkew;

        $this->isVerified  = $isVerified;
        $this->isValid     = $isValid;
        
        $this->checkIssuedAt();
        $this->checkExpiration();
    }

    /**
     * @return array
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * @return array
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * @return bool
     */
    public function isVerified()
    {
        return $this->isVerified;
    }

    /**
     * @return bool
     */
    public function isExpired()
    {
        return $this->isExpired;
    }

    /**
     * @return bool
     */
    public function isInvalid()
    {
        return !$this->isValid;
    }

    /**
     * Ensures that the signature is not expired.
     */
    private function checkExpiration()
    {
        
        
        if (!$this->hasLifetime) {
            return $this->isExpired = false;
        }

        if (!isset($this->payload['exp']) || !is_numeric($this->payload['exp'])) {
            return $this->isExpired = true;
        }

        if ($this->clockSkew <= time() - $this->payload['exp']) {
            return $this->isExpired = true;
        }

        // All good baby
        return $this->isExpired = false;
    }

    /**
     * Ensures that the iat claim is not in the future.
     */
    private function checkIssuedAt()
    {
        
        if (isset($this->payload['iat']) && (int) $this->payload['iat'] - $this->clockSkew > time()) {
            return $this->isValid = false;
        }

    }
}
