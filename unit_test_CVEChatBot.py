"""Test file for TelegramCVE Chatbot"""
"""Needs to be in same dir as CVEChatBot.py!"""

import unittest
import asyncio
from unittest.mock import MagicMock
from CVEChatBot import CVE_command, CPE_Command

class AsyncMock(MagicMock):
    """# The `AsyncMock` class is a subclass of `MagicMock` that allows for asynchronous calls.
    """
    async def __call__(self, *args, **kwargs):
        """
        The function is an asynchronous method that calls the parent class's
        method with the given arguments
        and keyword arguments.
        """
        return super(AsyncMock, self).__call__(*args, **kwargs)



class TestCVECommand(unittest.TestCase):
    """The class `TestCVECommand` contains a unit test method for testing a specific scenario of the
    `CVE_command` function."""
    def test_cve_command_with_keyword_cached(self):
        """
        The function `test_CVE_command_with_keyword_Cached` tests the `CVE_command`
        function with a specific
        keyword and mock objects.
        """
        update_mock = AsyncMock()
        context_mock = MagicMock()
        context_mock.args = ['keyword', 'apple']

        asyncio.run(CVE_command(update_mock, context_mock))

        update_mock.message.reply_text.assert_called_once()
        
    def test_cve_command_with_id_cached(self):
        """
        The function `test_cve_command_with_id_cached` tests the
        `CVE_command` function with a specific CVE
        ID provided as an argument.
        """
        update_mock = AsyncMock()
        context_mock = MagicMock()
        context_mock.args = ['id', 'CVE-2022-1234']

        asyncio.run(CVE_command(update_mock, context_mock))

        update_mock.message.reply_text.assert_called_once()

    def test_cpe_command_with_id_cached(self):
        """
        The function `test_CPE_command_with_id_Cached` tests the 
        `CPE_Command` function with a specific ID
        argument.
        """
        update_mock = AsyncMock()
        context_mock = MagicMock()
        context_mock.args = ['id', 'cpe:2.3:a:adobe:flash_player:-:*:*:*:*:*:*:*']

        asyncio.run(CPE_Command(update_mock, context_mock))

        update_mock.message.reply_text.assert_called_once()

    def test_cpe_command_with_keyword_cached(self):
        """
        The function `test_CPE_command_with_id_Cached` tests the
        `CPE_Command` function with specific
        arguments.
        """
        update_mock = AsyncMock()
        context_mock = MagicMock()
        context_mock.args = ['keyword', 'flash']

        asyncio.run(CPE_Command(update_mock, context_mock))

        update_mock.message.reply_text.assert_called_once()

if __name__ == '__main__':
    unittest.main()
