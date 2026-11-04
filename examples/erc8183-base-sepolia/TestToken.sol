// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// The escrow's payment token for this example: anyone can mint it, so it has no value.
contract TestToken is ERC20 {
    constructor() ERC20("ERC-8183 example token", "T8183") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
