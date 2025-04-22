"""
Unit tests for the dashboard functionality.
"""

import unittest
import sys
from pathlib import Path
import sqlite3
import os
import tempfile
import datetime as dt
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

# Import dashboard functions to test
from dashboard.dashboard import get_connection, create_tables_if_not_exist, insert_sample_data

class TestDashboard(unittest.TestCase):
    """Test cases for the dashboard functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for the test database
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_security_events.db")
        
        # Mock the DB_PATH in the dashboard module
        self.db_path_patcher = patch('dashboard.dashboard.DB_PATH', Path(self.db_path))
        self.db_path_mock = self.db_path_patcher.start()
    
    def tearDown(self):
        """Tear down test fixtures."""
        self.db_path_patcher.stop()
        self.temp_dir.cleanup()
    
    def test_get_connection(self):
        """Test database connection creation."""
        conn = get_connection()
        self.assertIsInstance(conn, sqlite3.Connection)
        conn.close()
    
    def test_create_tables(self):
        """Test creation of database tables."""
        # Create the tables
        create_tables_if_not_exist()
        
        # Verify tables were created
        conn = get_connection()
        cursor = conn.cursor()
        
        # Check security_events table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'")
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        
        # Check system_metrics table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_metrics'")
        result = cursor.fetchone()
        self.assertIsNotNone(result)
        
        conn.close()
    
    def test_insert_sample_data(self):
        """Test insertion of sample data."""
        # Create tables first
        create_tables_if_not_exist()
        
        # Insert sample data
        insert_sample_data()
        
        # Verify data was inserted
        conn = get_connection()
        cursor = conn.cursor()
        
        # Check security_events data
        cursor.execute("SELECT COUNT(*) FROM security_events")
        event_count = cursor.fetchone()[0]
        self.assertGreater(event_count, 0)
        
        # Check system_metrics data
        cursor.execute("SELECT COUNT(*) FROM system_metrics")
        metric_count = cursor.fetchone()[0]
        self.assertGreater(metric_count, 0)
        
        conn.close()
    
    def test_insert_sample_data_idempotent(self):
        """Test that sample data insertion is idempotent."""
        # Create tables first
        create_tables_if_not_exist()
        
        # Insert sample data twice
        insert_sample_data()
        
        # Count the records after first insertion
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM security_events")
        first_count = cursor.fetchone()[0]
        conn.close()
        
        # Insert again
        insert_sample_data()
        
        # Count again
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM security_events")
        second_count = cursor.fetchone()[0]
        conn.close()
        
        # Counts should be the same
        self.assertEqual(first_count, second_count)

    @patch('dashboard.dashboard.pd.read_sql_query')
    def test_update_active_threats(self, mock_read_sql):
        """Test the update_active_threats callback function."""
        from dashboard.dashboard import update_active_threats
        
        # Mock the pandas DataFrame result
        mock_df = MagicMock()
        mock_df.iloc.__getitem__.return_value.__getitem__.return_value = 5
        mock_read_sql.return_value = mock_df
        
        # Call the function
        result = update_active_threats(1)
        
        # Verify result
        self.assertEqual(result, 5)
        mock_read_sql.assert_called_once()

if __name__ == '__main__':
    unittest.main()
