Feature: Failed User Login
  Scenario: nonexisting user tried to log in
    Given we do not know that user
    When the nonexisting user tries to log in
    Then we do not log the user in
