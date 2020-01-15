# -*- coding: utf-8 -*-
"""Module implementing a simple hooks system to allow late-binding actions to
PyDOV events."""
import gzip
import os
from hashlib import md5
from owslib.etree import etree

import sys
from multiprocessing import Lock

import time

from pydov.util.errors import LogReplayError


class AbstractHook(object):
    """Abstract base class for custom hook implementations.

    Provides all available methods with a default implementation to do
    nothing. This allows for hook subclasses to only implement the events
    they need.

    """
    def meta_received(self, url, response):
        pass

    def inject_meta_response(self, url):
        return None

    def wfs_search_init(self, typename):
        """Called upon starting a WFS search.

        Parameters
        ----------
        typename : str
            The typename (layername) of the WFS service used for searching.

        """
        pass

    def wfs_search_query(self, query):
        """Called upon starting a WFS search.

        Includes the full WFS GetFeature request sent to the WFS server.

        Parameters
        ----------
        query : etree.ElementTree
            The WFS GetFeature request sent to the WFS server.

        """
        pass

    def wfs_search_result(self, number_of_results):
        """Called after a WFS search finished.

        Parameters
        ----------
        number_of_results : int
            The number of features returned by the WFS search.

        """
        pass

    def wfs_search_result_features(self, query, features):
        """Called after a WFS search finished.

        Includes the full response from the WFS GetFeature query.

        Parameters
        ----------
        query : etree.ElementTree
            The WFS GetFeature request sent to the WFS server.
        features : etree.ElementTree
            The WFS GetFeature response containings the features.

        """
        pass

    def inject_wfs_result_features(self, query):
        return None

    def xml_requested(self, pkey_object):
        """Called upon requesting an XML document of an object.

        Because of parallel processing, this method will be called
        simultaneously from multiple threads. Make sure your implementation is
        threadsafe or uses locking.

        This is either followed by ``xml_cache_hit`` or ``xml_downloaded``.

        Parameters
        ----------
        pkey_object : str
            Permanent key of the requested object.

        """
        pass

    def xml_cache_hit(self, pkey_object):
        """Called when the XML document of an object is retrieved from the
        cache.

        Because of parallel processing, this method will be called
        simultaneously from multiple threads. Make sure your implementation is
        threadsafe or uses locking.

        Parameters
        ----------
        pkey_object : str
            Permanent key of the requested object.

        """
        pass

    def xml_downloaded(self, pkey_object):
        """Called when the XML document of an object is downloaded from the
        DOV services.

        Because of parallel processing, this method will be called
        simultaneously from multiple threads. Make sure your implementation is
        threadsafe or uses locking.

        Parameters
        ----------
        pkey_object : str
            Permanent key of the requested object.

        """
        pass

    def xml_retrieved(self, pkey_object, xml):
        """Called when the XML of a given object is retrieved, either from
        the cache or from the remote DOV service.

        Includes the permanent key of the DOV object as well as the full XML
        representation.

        Parameters
        ----------
        pkey_object : str
            Permanent key of the retrieved object.
        xml : bytes
            The raw XML data of this DOV object as bytes.

        """
        pass

    def inject_xml_retrieved(self, pkey_object):
        return None


class SimpleStatusHook(AbstractHook):
    """Simple hook implementation to print progress to stdout."""
    def __init__(self):
        """Initialisation.

        Initialise all variables to 0.

        """
        self.result_count = 0
        self.prog_counter = 0
        self.init_time = None
        self.previous_remaining = None
        self.lock = Lock()

    def _write_progress(self, char):
        """Write progress to standard output.

        Progress is grouped on lines per 50 items, adding ``char`` for every
        item processed.

        Parameters
        ----------
        char : str
            Single character to print.

        """
        if self.prog_counter == 0:
            sys.stdout.write('[{:03d}/{:03d}] '.format(
                self.prog_counter, self.result_count))
            sys.stdout.flush()
        elif self.prog_counter % 50 == 0:
            time_elapsed = time.time() - self.init_time
            time_per_item = time_elapsed/self.prog_counter
            remaining_mins = int((time_per_item*(
                self.result_count-self.prog_counter))/60)
            if remaining_mins > 1 and remaining_mins != \
                    self.previous_remaining:
                remaining = " ({:d} min. left)".format(remaining_mins)
                self.previous_remaining = remaining_mins
            else:
                remaining = ""
            sys.stdout.write('{}\n[{:03d}/{:03d}] '.format(
                remaining, self.prog_counter, self.result_count))
            sys.stdout.flush()

        sys.stdout.write(char)
        sys.stdout.flush()
        self.prog_counter += 1

        if self.prog_counter == self.result_count:
            sys.stdout.write('\n')
            sys.stdout.flush()

    def wfs_search_init(self, typename):
        """When a new WFS search is started, reset all counters to 0.

        Parameters
        ----------
        typename : str
            The typename (layername) of the WFS service used for searching.

        """
        self.result_count = 0
        self.prog_counter = 0
        self.init_time = time.time()
        self.previous_remaining = None

    def wfs_search_result(self, number_of_results):
        """When the WFS search completes, set the total result count to
        ``number_of_results``.

        Parameters
        ----------
        number_of_results : int
            The number of features returned by the WFS search.

        """
        self.result_count = number_of_results

    def xml_cache_hit(self, pkey_object):
        """When an XML document is retrieved from the cache, print 'c' to
        the progress output.

        Parameters
        ----------
        pkey_object : str
            Permanent key of the requested object.

        """
        with self.lock:
            self._write_progress('c')

    def xml_downloaded(self, pkey_object):
        """When an XML document is downloaded from the DOV services,
        print '.' to the progress output.

        Parameters
        ----------
        pkey_object : str
            Permanent key of the requested object.

        """
        with self.lock:
            self._write_progress('.')


class LogHook(AbstractHook):
    class Mode:
        Record, Replay = range(2)

    def __init__(self, log_directory, mode):
        # todo: werken met zipfile ipv directory?
        self.log_directory = log_directory
        self.mode = mode

        if not os.path.exists(os.path.join(log_directory, 'meta')):
            os.makedirs(os.path.join(log_directory, 'meta'))

        if not os.path.exists(os.path.join(log_directory, 'wfs')):
            os.makedirs(os.path.join(log_directory, 'wfs'))

        if not os.path.exists(os.path.join(log_directory, 'xml')):
            os.makedirs(os.path.join(log_directory, 'xml'))

    def meta_received(self, url, response):
        if self.mode == LogHook.Mode.Record:
            hash = md5(url.encode('utf8')).hexdigest()
            log_path = os.path.join(self.log_directory, 'meta', hash + '.log')

            with open(log_path, 'w') as log_file:
                log_file.write(response.decode('utf8'))

    def inject_meta_response(self, url):
        if self.mode == LogHook.Mode.Replay:
            hash = md5(url.encode('utf8')).hexdigest()
            log_path = os.path.join(self.log_directory, 'meta', hash + '.log')

            if not os.path.isfile(log_path):
                raise LogReplayError(
                    'Failed to replay log: no entry for '
                    'meta response of {}.'.format(hash)
                )

            with open(log_path, 'r') as log_file:
                response = log_file.read().encode('utf8')

            return response

    def wfs_search_result_features(self, query, features):
        if self.mode == LogHook.Mode.Record:
            q = etree.tostring(query, encoding='unicode')

            hash = md5(q.encode('utf8')).hexdigest()
            log_path = os.path.join(self.log_directory, 'wfs', hash + '.log')

            with open(log_path, 'w') as log_file:
                log_file.write(
                    etree.tostring(features, encoding='utf8').decode('utf8'))

    def inject_wfs_result_features(self, query):
        if self.mode == LogHook.Mode.Replay:
            q = etree.tostring(query, encoding='unicode')
            hash = md5(q.encode('utf8')).hexdigest()

            log_path = os.path.join(self.log_directory, 'wfs', hash + '.log')

            if not os.path.isfile(log_path):
                raise LogReplayError(
                    'Failed to replay log: no entry for '
                    'WFS result of {}.'.format(hash)
                )

            with open(log_path, 'r') as log_file:
                tree = log_file.read().encode('utf8')

            return tree

    def xml_retrieved(self, pkey_object, xml):
        if self.mode == LogHook.Mode.Record:
            hash = md5(pkey_object.encode('utf8')).hexdigest()
            log_path = os.path.join(self.log_directory, 'xml', hash + '.log')

            with open(log_path, 'w') as log_file:
                log_file.write(xml.decode('utf8'))

    def inject_xml_retrieved(self, pkey_object):
        if self.mode == LogHook.Mode.Replay:
            hash = md5(pkey_object.encode('utf8')).hexdigest()
            log_path = os.path.join(self.log_directory, 'xml', hash + '.log')

            if not os.path.isfile(log_path):
                raise LogReplayError(
                    'Failed to replay log: no entry for '
                    'XML result of {}.'.format(hash)
                )

            with open(log_path, 'r') as log_file:
                xml = log_file.read().encode('utf8')

            return xml
