//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Storage is Ownable {
  string[] private values;

  function addValue(string calldata v) public onlyOwner {
    values.push(v);
  }
  function getValues() public view returns(string[] memory) {
    return values;
  }
}
