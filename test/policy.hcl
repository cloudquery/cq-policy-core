policy "test-policy" {
  description = "Test Policy"
  configuration {
    provider "aws" {
      version = ">= 1.0"
    }
  }

  view "testview" {
    description = "Test View"
    query "testviewquery" {
      query = "SELECT * FROM test_policy_table WHERE name LIKE 'john'"
    }
  }

  query "top-level-query" {
    description = "Top Level Query"
    query = "SELECT * FROM test_policy_table WHERE name LIKE 'peter'"
  }

  policy "sub-policy-1" {
    description = "Sub Policy 1"
    query "sub-level-query" {
      query = "SELECT * from testview"
      expect_output = true
    }
  }

  policy "sub-policy-2" {
    description = "Sub Policy 2"
    query "sub-level-query" {
      query = "SELECT * from test_policy_table WHERE name LIKE 'peter'"
    }
  }
}