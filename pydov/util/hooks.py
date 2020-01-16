# -*- coding: utf-8 -*-
"""Module implementing a simple hooks system to allow late-binding actions to
PyDOV events."""
import atexit
import json
import os
import uuid
import zipfile
from hashlib import md5
from pathlib import Path

import pydov
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


class RepeatableLogRecorder(AbstractHook):
    def __init__(self, log_directory):
        self.log_directory = log_directory
        self.log_archive = os.path.join(
            self.log_directory,
            time.strftime('pydov-archive-%Y%m%dT%H%M%S-{}.zip'.format(
                uuid.uuid4()))
        )

        self.log_archive_file = zipfile.ZipFile(
            self.log_archive, 'w', compression=zipfile.ZIP_DEFLATED)

        self.metadata = {
            'pydov_version' : pydov.__version__,
            'start_run': time.strftime('%Y%m%d-%H%M%S')
        }
        self.started_at = time.perf_counter()

        pydov_root = Path(pydov.__file__).parent
        for f in pydov_root.glob('**\\*.py'):
            self.log_archive_file.write(
                str(f), 'pydov/' + str(f.relative_to(pydov_root)))

        self.lock = Lock()

        atexit.register(self.pydov_exit)

    def pydov_exit(self):
        self.metadata['end_run'] = time.strftime('%Y%m%d-%H%M%S')
        self.metadata['ran_for'] = time.perf_counter() - self.started_at

        self.log_archive_file.writestr(
            'metadata.json', json.dumps(self.metadata, indent=2))
        self.log_archive_file.close()

    def meta_received(self, url, response):
        hash = md5(url.encode('utf8')).hexdigest()
        log_path = 'meta/' + hash + '.log'

        if log_path not in self.log_archive_file.namelist():
            self.log_archive_file.writestr(log_path, response.decode('utf8'))

    def inject_meta_response(self, url):
        hash = md5(url.encode('utf8')).hexdigest()
        log_path = 'meta/' + hash + '.log'

        if log_path not in self.log_archive_file.namelist():
            return None

        with self.log_archive_file.open(log_path, 'r') as log_file:
            response = log_file.read().decode('utf8')

        return response

    def wfs_search_result_features(self, query, features):
        q = etree.tostring(query, encoding='unicode')
        hash = md5(q.encode('utf8')).hexdigest()
        log_path = 'wfs/' + hash + '.log'

        if log_path not in self.log_archive_file.namelist():
            self.log_archive_file.writestr(
                log_path,
                etree.tostring(features, encoding='utf8').decode('utf8'))

    def inject_wfs_result_features(self, query):
        q = etree.tostring(query, encoding='unicode')
        hash = md5(q.encode('utf8')).hexdigest()
        log_path = 'wfs/' + hash + '.log'

        if log_path not in self.log_archive_file.namelist():
            return None

        with self.log_archive_file.open(log_path, 'r') as log_file:
            tree = log_file.read().decode('utf8')

        return tree

    def xml_retrieved(self, pkey_object, xml):
        with self.lock:
            hash = md5(pkey_object.encode('utf8')).hexdigest()
            log_path = 'xml/' + hash + '.log'

            if log_path not in self.log_archive_file.namelist():
                self.log_archive_file.writestr(log_path, xml.decode('utf8'))

    def inject_xml_retrieved(self, pkey_object):
        with self.lock:
            hash = md5(pkey_object.encode('utf8')).hexdigest()
            log_path = 'xml/' + hash + '.log'

            if log_path not in self.log_archive_file.namelist():
                return None

            with self.log_archive_file.open(log_path, 'r') as log_file:
                xml = log_file.read().decode('utf8')

            return xml


class RepeatableLogReplayer(AbstractHook):
    def __init__(self, log_archive):
        self.log_archive = log_archive

        self.log_archive_file = zipfile.ZipFile(
            self.log_archive, 'r', compression=zipfile.ZIP_DEFLATED)

        self.lock = Lock()

        atexit.register(self.pydov_exit)

    def pydov_exit(self):
        self.log_archive_file.close()

    def inject_meta_response(self, url):
        hash = md5(url.encode('utf8')).hexdigest()
        log_path = 'meta/' + hash + '.log'

        if log_path not in self.log_archive_file.namelist():
            raise LogReplayError(
                'Failed to replay log: no entry for '
                'meta response of {}.'.format(hash)
            )

        with self.log_archive_file.open(log_path, 'r') as log_file:
            response = log_file.read().decode('utf8')

        return response

    def inject_wfs_result_features(self, query):
        q = etree.tostring(query, encoding='unicode')
        hash = md5(q.encode('utf8')).hexdigest()
        log_path = 'wfs/' + hash + '.log'

        if log_path not in self.log_archive_file.namelist():
            raise LogReplayError(
                'Failed to replay log: no entry for '
                'WFS result of {}.'.format(hash)
            )

        with self.log_archive_file.open(log_path, 'r') as log_file:
            tree = log_file.read().decode('utf8')

        return tree

    def inject_xml_retrieved(self, pkey_object):
        with self.lock:
            hash = md5(pkey_object.encode('utf8')).hexdigest()
            log_path = 'xml/' + hash + '.log'

            if log_path not in self.log_archive_file.namelist():
                raise LogReplayError(
                    'Failed to replay log: no entry for '
                    'XML result of {}.'.format(hash)
                )

            with self.log_archive_file.open(log_path, 'r') as log_file:
                xml = log_file.read().decode('utf8')

            return xml
