<?php

/**
 * SC Alwaysdata - PrestaShop 8 Module
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

namespace ScAlwaysdata\Service;

/**
 * Another request is already computing the same diagnostic entry.
 */
class DiagnosticBusyException extends \RuntimeException
{
}
