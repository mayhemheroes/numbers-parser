import math
import re

from array import array
from functools import lru_cache
from struct import pack
from typing import Dict, List, Tuple
from warnings import warn

from numbers_parser.containers import ObjectStore
from numbers_parser.constants import (
    EPOCH,
    DEFAULT_COLUMN_WIDTH,
    DEFAULT_DOCUMENT,
    DEFAULT_PRE_BNC_BYTES,
    DEFAULT_ROW_HEIGHT,
    DEFAULT_TABLE_OFFSET,
    DEFAULT_TILE_SIZE,
    DOCUMENT_ID,
    PACKAGE_ID,
    MAX_TILE_SIZE,
)
from numbers_parser.cell import (
    xl_rowcol_to_cell,
    xl_col_to_name,
    BoolCell,
    DateCell,
    DurationCell,
    EmptyCell,
    MergedCell,
    NumberCell,
    TextCell,
)
from numbers_parser.exceptions import UnsupportedError, UnsupportedWarning
from numbers_parser.formula import TableFormulas
from numbers_parser.bullets import (
    BULLET_PREFIXES,
    BULLET_CONVERTION,
    BULLET_SUFFIXES,
)
from numbers_parser.cell_storage import CellStorage
from numbers_parser.numbers_uuid import NumbersUUID

from numbers_parser.generated import TNArchives_pb2 as TNArchives
from numbers_parser.generated import TSDArchives_pb2 as TSDArchives
from numbers_parser.generated import TSPMessages_pb2 as TSPMessages
from numbers_parser.generated import TSPArchiveMessages_pb2 as TSPArchiveMessages
from numbers_parser.generated import TSTArchives_pb2 as TSTArchives
from numbers_parser.generated import TSCEArchives_pb2 as TSCEArchives


class DataLists:
    """Model for TST.DataList with caching and key generation for new values"""

    def __init__(self, model: object, datalist_name: str, value_attr: str = None):
        self._model = model
        self._datalists = {}
        self._value_attr = value_attr
        self._datalist_name = datalist_name

    def add_table(self, table_id: int):
        """Cache a new datalist for a table if not already seen"""
        if table_id not in self._datalists:
            base_data_store = self._model.objects[table_id].base_data_store
            datalist_id = getattr(base_data_store, self._datalist_name).identifier
            datalist = self._model.objects[datalist_id]

            max_key = 0
            self._datalists[table_id] = {}
            self._datalists[table_id]["by_key"] = {}
            self._datalists[table_id]["by_value"] = {}
            self._datalists[table_id]["datalist"] = datalist.entries
            for entry in datalist.entries:
                if entry.key > max_key:
                    max_key = entry.key
                    self._datalists[table_id]["by_key"][entry.key] = entry
                    if self._value_attr is not None:
                        value = getattr(entry, self._value_attr)
                        self._datalists[table_id]["by_value"][value] = entry.key
            self._datalists[table_id]["next_key"] = max_key + 1

    def lookup_value(self, table_id: int, key: int):
        """Return the an entry in a table's datalist matching a key"""
        return self._datalists[table_id]["by_key"][key]

    def init(self, table_id: int):
        """Remove all entries from a datalist"""
        self.add_table(table_id)
        self._datalists[table_id]["by_key"] = {}
        self._datalists[table_id]["by_value"] = {}
        self._datalists[table_id]["next_key"] = 1
        clear_field_container(self._datalists[table_id]["datalist"])

    def lookup_key(self, table_id: int, value) -> int:
        """Return the key associated with a value for a particular table entry.
        If the value is not in the datalist, allocate a new entry with the
        next available key"""
        self.add_table(table_id)
        if value not in self._datalists[table_id]["by_value"]:
            key = self._datalists[table_id]["next_key"]
            self._datalists[table_id]["next_key"] += 1
            attrs = {"key": key, self._value_attr: value, "refcount": 1}
            entry = TSTArchives.TableDataList.ListEntry(**attrs)
            self._datalists[table_id]["datalist"].append(entry)
            self._datalists[table_id]["by_key"][key] = entry
        else:
            key = self._datalists[table_id]["by_value"][value]
            self._datalists[table_id]["by_key"][key].refcount += 1

        return key


class _NumbersModel:
    """
    Loads all objects from Numbers document and provides decoding
    methods for other classes in the module to abstract away the
    internal structures of Numbers document data structures.

    Not to be used in application code.
    """

    def __init__(self, filename):
        if filename is None:
            filename = DEFAULT_DOCUMENT
        self.objects = ObjectStore(filename)
        # self._table_strings = {}
        self._merge_cells = {}
        self._row_heights = {}
        self._col_widths = {}
        self._table_formats = DataLists(self, "format_table")
        self._table_styles = DataLists(self, "styleTable")
        self._table_strings = DataLists(self, "stringTable", "string")

    @property
    def file_store(self):
        return self.objects.file_store

    def find_refs(self, ref: str) -> list:
        return self.objects.find_refs(ref)

    def sheet_ids(self):
        return [o.identifier for o in self.objects[DOCUMENT_ID].sheets]

    def sheet_name(self, sheet_id, value=None):
        if value is None:
            return self.objects[sheet_id].name
        else:
            self.objects[sheet_id].name = value

    # Don't cache: new tables can be added at runtime
    def table_ids(self, sheet_id: int) -> list:
        """Return a list of table IDs for a given sheet ID"""
        table_info_ids = self.find_refs("TableInfoArchive")
        return [
            self.objects[t_id].tableModel.identifier
            for t_id in table_info_ids
            if self.objects[t_id].super.parent.identifier == sheet_id
        ]

    # Don't cache: new tables can be added at runtime
    def table_info_id(self, table_id: int) -> int:
        """Return the TableInfoArchive ID for a given table ID"""
        ids = [
            x
            for x in self.objects.find_refs("TableInfoArchive")
            if self.objects[x].tableModel.identifier == table_id
        ]
        return ids[0]

    @lru_cache(maxsize=None)
    def row_storage_map(self, table_id):
        # The base data store contains a reference to rowHeaders.buckets
        # which is an ordered list that matches the storage buffers, but
        # identifies which row a storage buffer belongs to (empty rows have
        # no storage buffers). Each bucket is:
        #
        #  {
        #      "hiding_state": 0,
        #      "index": 0,
        #      "number_of_cells": 3,
        #      "size": 0.0
        #  },
        row_bucket_map = {i: None for i in range(self.objects[table_id].number_of_rows)}
        bds = self.objects[table_id].base_data_store
        buckets = self.objects[bds.rowHeaders.buckets[0].identifier].headers
        for i, bucket in enumerate(buckets):
            row_bucket_map[bucket.index] = i
        return row_bucket_map

    def number_of_rows(self, table_id, num_rows=None):
        if num_rows is not None:
            self.objects[table_id].number_of_rows = num_rows
        return self.objects[table_id].number_of_rows

    def number_of_columns(self, table_id, num_cols=None):
        if num_cols is not None:
            self.objects[table_id].number_of_columns = num_cols
        return self.objects[table_id].number_of_columns

    @lru_cache(maxsize=None)
    def col_storage_map(self, table_id: int):
        # The base data store contains a reference to columnHeaders
        # which is an ordered list that identfies which offset to use
        # to index storage buffers for each column.
        #
        #  {
        #      "hiding_state": 0,
        #      "index": 0,
        #      "number_of_cells": 3,
        #      "size": 0.0
        #  },
        col_bucket_map = {
            i: None for i in range(self.objects[table_id].number_of_columns)
        }
        bds = self.objects[table_id].base_data_store
        buckets = self.objects[bds.columnHeaders.identifier].headers
        for i, bucket in enumerate(buckets):
            col_bucket_map[bucket.index] = i
        return col_bucket_map

    def table_name(self, table_id, value=None):
        if value is None:
            return self.objects[table_id].table_name
        else:
            self.objects[table_id].table_name = value

    @lru_cache(maxsize=None)
    def table_tiles(self, table_id):
        bds = self.objects[table_id].base_data_store
        return [self.objects[t.tile.identifier] for t in bds.tiles.tiles]

    @lru_cache(maxsize=None)
    def custom_format_map(self):
        custom_format_list_id = self.objects[
            DOCUMENT_ID
        ].super.custom_format_list.identifier
        custom_format_list = self.objects[custom_format_list_id]
        custom_format_map = {
            NumbersUUID(u).hex: custom_format_list.custom_formats[i]
            for i, u in enumerate(custom_format_list.uuids)
        }
        return custom_format_map

    @lru_cache(maxsize=None)
    def table_format(self, table_id: int, key: int) -> str:
        """Return the format associated with a format ID for a particular table"""
        self._table_formats.add_table(table_id)
        return self._table_formats.lookup_value(table_id, key).format

    @lru_cache(maxsize=None)
    def table_style(self, table_id: int, key: int) -> str:
        """Return the style associated with a style ID for a particular table"""
        self._table_styles.add_table(table_id)
        style_entry = self._table_styles.lookup_value(table_id, key)
        return self.objects[style_entry.reference.identifier]

    @lru_cache(maxsize=None)
    def table_string(self, table_id: int, key: int) -> str:
        """Return the string assocuated with a string ID for a particular table"""
        self._table_strings.add_table(table_id)
        return self._table_strings.lookup_value(table_id, key).string

    def init_table_strings(self, table_id: int):
        """Cache table strings reference and delete all existing keys/values"""
        self._table_strings.init(table_id)

    def table_string_key(self, table_id: int, value: str) -> int:
        """Return the key associated with a string for a particular table. If
        the string is not in the strings table, allocate a new entry with the
        next available key"""
        return self._table_strings.lookup_key(table_id, value)

    @lru_cache(maxsize=None)
    def owner_id_map(self):
        """ "
        Extracts the mapping table from Owner IDs to UUIDs. Returns a
        dictionary mapping the owner ID int to a 128-bit UUID.
        """
        # The TSCE.CalculationEngineArchive contains a list of mapping entries
        # in dependencyTracker.formulaOwnerDependencies from the root level
        # of the protobuf. Each mapping contains a 32-bit style UUID:
        #
        # "owner_id_map": {
        #     "map_entry": [
        #     {
        #         "internal_ownerId": 33,
        #         "owner_id": 0x3cb03f23_c26dda92_1e4bfcc0_8750e563
        #     },
        #
        #
        calc_engine = self.calc_engine()
        if calc_engine is None:
            return {}

        owner_id_map = {}
        for e in calc_engine.dependency_tracker.owner_id_map.map_entry:
            owner_id_map[e.internal_owner_id] = NumbersUUID(e.owner_id).hex
        return owner_id_map

    @lru_cache(maxsize=None)
    def table_base_id(self, table_id: int) -> int:
        """ "Finds the UUID of a table"""
        # Look for a TSCE.FormulaOwnerDependenciesArchive objects with the following at the
        # root level of the protobuf:
        #
        #     "base_owner_uid": "6a4a5281-7b06-f5a1-904b-7f9ec784b368"",
        #     "formula_owner_uid": "6a4a5281-7b06-f5a1-904b-7f9ec784b36d"
        #
        # The Table UUID is the TSCE.FormulaOwnerDependenciesArchive whose formula_owner_uid
        # matches the UUID of the haunted_owner of the Table:
        #
        #    "haunted_owner": {
        #        "owner_uid": "6a4a5281-7b06-f5a1-904b-7f9ec784b368""
        #    }
        haunted_owner = NumbersUUID(self.objects[table_id].haunted_owner.owner_uid).hex
        formula_owner_ids = self.find_refs("FormulaOwnerDependenciesArchive")
        for dependency_id in formula_owner_ids:  # pragma: no branch
            obj = self.objects[dependency_id]
            if obj.HasField("base_owner_uid") and obj.HasField(
                "formula_owner_uid"
            ):  # pragma: no branch
                base_owner_uid = NumbersUUID(obj.base_owner_uid).hex
                formula_owner_uid = NumbersUUID(obj.formula_owner_uid).hex
                if formula_owner_uid == haunted_owner:
                    return base_owner_uid

    @lru_cache(maxsize=None)
    def formula_cell_ranges(self, table_id: int) -> list:
        """Exract all the formula cell ranges for the Table."""
        # https://github.com/masaccio/numbers-parser/blob/main/doc/Numbers.md#formula-ranges
        calc_engine = self.calc_engine()
        if calc_engine is None:  # pragma: no cover
            return []

        table_base_id = self.table_base_id(table_id)
        cell_records = []
        for finfo in calc_engine.dependency_tracker.formula_owner_info:
            if finfo.HasField("cell_dependencies"):  # pragma: no branch
                formula_owner_id = NumbersUUID(finfo.formula_owner_id).hex
                if formula_owner_id == table_base_id:
                    for cell_record in finfo.cell_dependencies.cell_record:
                        if cell_record.contains_a_formula:  # pragma: no branch
                            cell_records.append((cell_record.row, cell_record.column))
        return cell_records

    @lru_cache(maxsize=None)
    def calc_engine_id(self):
        """Return the CalculationEngine ID for the current document"""
        ce_id = self.find_refs("CalculationEngineArchive")
        if len(ce_id) == 0:
            return 0
        else:
            return ce_id[0]

    @lru_cache(maxsize=None)
    def calc_engine(self):
        """Return the CalculationEngine object for the current document"""
        ce_id = self.calc_engine_id()
        if ce_id == 0:
            return None
        else:
            return self.objects[ce_id]

    def calculate_merge_cell_ranges(self, table_id):
        """Exract all the merge cell ranges for the Table."""
        # https://github.com/masaccio/numbers-parser/blob/main/doc/Numbers.md#merge-ranges
        owner_id_map = self.owner_id_map()
        table_base_id = self.table_base_id(table_id)

        merge_cells = {}
        range_table_ids = self.find_refs("RangePrecedentsTileArchive")
        for range_id in range_table_ids:
            o = self.objects[range_id]
            to_owner_id = o.to_owner_id
            if owner_id_map[to_owner_id] == table_base_id:
                for from_to_range in o.from_to_range:
                    rect = from_to_range.refers_to_rect
                    row_start = rect.origin.row
                    row_end = row_start + rect.size.num_rows - 1
                    col_start = rect.origin.column
                    col_end = col_start + rect.size.num_columns - 1
                    for row_num in range(row_start, row_end + 1):
                        for col_num in range(col_start, col_end + 1):
                            merge_cells[(row_num, col_num)] = {
                                "merge_type": "ref",
                                "rect": (row_start, col_start, row_end, col_end),
                                "size": (rect.size.num_rows, rect.size.num_columns),
                            }
                    merge_cells[(row_start, col_start)]["merge_type"] = "source"
        self._merge_cells[table_id] = merge_cells

        bds = self.objects[table_id].base_data_store
        if bds.merge_region_map.identifier != 0:
            cell_range = self.objects[bds.merge_region_map.identifier]
        else:
            return merge_cells

        for cell_range in cell_range.cell_range:
            (col_start, row_start) = (
                cell_range.origin.packedData >> 16,
                cell_range.origin.packedData & 0xFFFF,
            )
            (num_columns, num_rows) = (
                cell_range.size.packedData >> 16,
                cell_range.size.packedData & 0xFFFF,
            )
            row_end = row_start + num_rows - 1
            col_end = col_start + num_columns - 1
            for row_num in range(row_start, row_end + 1):
                for col_num in range(col_start, col_end + 1):
                    merge_cells[(row_num, col_num)] = {
                        "merge_type": "ref",
                        "rect": (row_start, col_start, row_end, col_end),
                        "size": (num_rows, num_columns),
                    }
        merge_cells[(row_start, col_start)]["merge_type"] = "source"

        return merge_cells

    def merge_cell_ranges(self, table_id):
        if table_id not in self._merge_cells:
            self._merge_cells[table_id] = self.calculate_merge_cell_ranges(table_id)
        return self._merge_cells[table_id]

    @lru_cache(maxsize=None)
    def table_uuids_to_id(self, table_uuid):
        for t_id in self.find_refs("TableInfoArchive"):  # pragma: no branch
            table_model_id = self.objects[t_id].tableModel.identifier
            if table_uuid == self.table_base_id(table_model_id):
                return table_model_id

    def node_to_ref(self, row_num: int, col_num: int, node):
        table_name = None
        if node.HasField("AST_cross_table_reference_extra_info"):
            table_uuid = NumbersUUID(
                node.AST_cross_table_reference_extra_info.table_id
            ).hex
            table_id = self.table_uuids_to_id(table_uuid)
            table_name = self.table_name(table_id)

        if node.HasField("AST_column") and not node.HasField("AST_row"):
            return node_to_col_ref(node, table_name, col_num)
        else:
            return node_to_row_col_ref(node, table_name, row_num, col_num)

    @lru_cache(maxsize=None)
    def formula_ast(self, table_id: int):
        bds = self.objects[table_id].base_data_store
        formula_table_id = bds.formula_table.identifier
        formula_table = self.objects[formula_table_id]
        formulas = {}
        for formula in formula_table.entries:
            formulas[formula.key] = formula.formula.AST_node_array.AST_node
        return formulas

    @lru_cache(maxsize=None)
    def storage_buffers(self, table_id: int) -> List:
        buffers = []
        for tile in self.table_tiles(table_id):
            if not tile.last_saved_in_BNC:  # pragma: no cover
                raise UnsupportedError("Pre-BNC storage is unsupported")
            for r in tile.rowInfos:
                buffer = get_storage_buffers_for_row(
                    r.cell_storage_buffer,
                    r.cell_offsets,
                    self.number_of_columns(table_id),
                    r.has_wide_offsets,
                )
                buffers.append(buffer)
        return buffers

    @lru_cache(maxsize=None)
    def storage_buffer(self, table_id: int, row_num: int, col_num: int) -> bytes:
        row_offset = self.row_storage_map(table_id)[row_num]
        if row_offset is None:
            return None
        try:
            storage_buffers = self.storage_buffers(table_id)
            return storage_buffers[row_offset][col_num]
        except IndexError:
            return None

    def recalculate_row_headers(self, table_id: int, data: List):
        base_data_store = self.objects[table_id].base_data_store
        buckets = self.objects[base_data_store.rowHeaders.buckets[0].identifier]
        clear_field_container(buckets.headers)
        for row_num in range(len(data)):
            if table_id in self._row_heights and row_num in self._row_heights[table_id]:
                height = self._row_heights[table_id][row_num]
            else:
                height = 0.0
            header = TSTArchives.HeaderStorageBucket.Header(
                index=row_num,
                numberOfCells=len(data[row_num]),
                size=height,
                hidingState=0,
            )
            buckets.headers.append(header)

    def recalculate_column_headers(self, table_id: int, data: List):
        base_data_store = self.objects[table_id].base_data_store
        buckets = self.objects[base_data_store.columnHeaders.identifier]
        clear_field_container(buckets.headers)
        # Transpose data to get columns
        col_data = [list(x) for x in zip(*data)]

        for col_num, col in enumerate(col_data):
            num_rows = len(col) - sum([isinstance(x, MergedCell) for x in col])
            if table_id in self._col_widths and col_num in self._col_widths[table_id]:
                width = self._col_widths[table_id][col_num]
            else:
                width = 0.0
            header = TSTArchives.HeaderStorageBucket.Header(
                index=col_num, numberOfCells=num_rows, size=width, hidingState=0
            )
            buckets.headers.append(header)

    def recalculate_merged_cells(self, table_id: int):
        merge_cells = self.merge_cell_ranges(table_id)
        if len(merge_cells) == 0:
            return

        merge_map_id, merge_map = self.objects.create_object_from_dict(
            "CalculationEngine", {}, TSTArchives.MergeRegionMapArchive
        )

        for merge_cell, merge_data in merge_cells.items():
            if merge_data["merge_type"] == "source":
                cell_id = TSTArchives.CellID(
                    packedData=(merge_cell[1] << 16 | merge_cell[0])
                )
                table_size = TSTArchives.TableSize(
                    packedData=(merge_data["size"][1] << 16 | merge_data["size"][0])
                )
                cell_range = TSTArchives.CellRange(origin=cell_id, size=table_size)
                merge_map.cell_range.append(cell_range)

        base_data_store = self.objects[table_id].base_data_store
        base_data_store.merge_region_map.CopyFrom(
            TSPMessages.Reference(identifier=merge_map_id)
        )

    def recalculate_row_info(
        self, table_id: int, data: List, tile_row_offset: int, row_num: int
    ) -> TSTArchives.TileRowInfo:
        row_info = TSTArchives.TileRowInfo()
        row_info.storage_version = 5
        row_info.tile_row_index = row_num - tile_row_offset
        row_info.cell_count = 0
        cell_storage = b""

        offsets = [-1] * len(data[0])
        current_offset = 0

        for col_num in range(len(data[row_num])):
            buffer = self.pack_cell_storage(table_id, data, row_num, col_num)
            if buffer is not None:
                cell_storage += buffer
                # Always use wide offsets
                offsets[col_num] = current_offset >> 2
                current_offset += len(buffer)

                row_info.cell_count += 1

        row_info.cell_offsets = pack(f"<{len(offsets)}h", *offsets)
        row_info.cell_offsets_pre_bnc = DEFAULT_PRE_BNC_BYTES
        row_info.cell_storage_buffer = cell_storage
        row_info.cell_storage_buffer_pre_bnc = DEFAULT_PRE_BNC_BYTES
        row_info.has_wide_offsets = True
        return row_info

    @lru_cache(maxsize=None)
    def metadata_component(self, component_name: str) -> int:
        """Return the ID of an object in the document metadata given it's name"""
        component_map = {c.identifier: c for c in self.objects[PACKAGE_ID].components}
        component_ids = [
            id
            for id, c in component_map.items()
            if c.preferred_locator == component_name
        ]
        return component_map[component_ids[0]]

    def add_component_metadata(self, object_id: int, parent: str, locator: str):
        """Add a new ComponentInfo record to the parent object in the document metadata"""
        locator = locator.format(object_id)
        preferred_locator = re.sub(r"\-\d+.*", "", locator)
        component_info = TSPArchiveMessages.ComponentInfo(
            identifier=object_id,
            locator=locator,
            preferred_locator=preferred_locator,
            is_stored_outside_object_archive=False,
            document_read_version=[2, 0, 0],
            document_write_version=[2, 0, 0],
            save_token=1,
        )
        self.objects[PACKAGE_ID].components.append(component_info)
        self.add_component_reference(object_id, parent)

    def add_component_reference(
        self,
        object_id: int,
        location: str,
        parent_id: int = None,
        is_weak: bool = False,
    ):
        """Add an external reference to an object in a metadata component"""
        component = self.metadata_component(location)
        if parent_id is not None:
            params = {"object_identifier": object_id, "component_identifier": parent_id}
        else:
            params = {"component_identifier": object_id}
        if is_weak:
            params["is_weak"] = True
        component.external_references.append(
            TSPArchiveMessages.ComponentExternalReference(**params)
        )

    def recalculate_table_data(self, table_id: int, data: List):
        table_model = self.objects[table_id]
        table_model.number_of_rows = len(data)
        table_model.number_of_columns = len(data[0])

        self.init_table_strings(table_id)
        self.recalculate_row_headers(table_id, data)
        self.recalculate_column_headers(table_id, data)
        self.recalculate_merged_cells(table_id)

        table_model.ClearField("base_column_row_uids")

        tile_idx = 0
        max_tile_idx = len(data) >> 8
        base_data_store = self.objects[table_id].base_data_store
        base_data_store.tiles.ClearField("tiles")
        if len(data[0]) > MAX_TILE_SIZE:
            base_data_store.tiles.should_use_wide_rows = True

        while tile_idx <= max_tile_idx:
            row_start = tile_idx * MAX_TILE_SIZE
            if (len(data) - row_start) > MAX_TILE_SIZE:
                num_rows = MAX_TILE_SIZE
                row_end = row_start + MAX_TILE_SIZE
            else:
                num_rows = len(data) - row_start
                row_end = row_start + num_rows

            tile_dict = {
                "maxColumn": 0,
                "maxRow": 0,
                "numCells": 0,
                "numrows": num_rows,
                "storage_version": 5,
                "rowInfos": [],
                "last_saved_in_BNC": True,
                "should_use_wide_rows": True,
            }
            tile_id, tile = self.objects.create_object_from_dict(
                "Index/Tables/Tile-{}", tile_dict, TSTArchives.Tile
            )
            for row_num in range(row_start, row_end):
                row_info = self.recalculate_row_info(table_id, data, row_start, row_num)
                tile.rowInfos.append(row_info)

            tile_ref = TSTArchives.TileStorage.Tile()
            tile_ref.tileid = tile_idx
            tile_ref.tile.MergeFrom(TSPMessages.Reference(identifier=tile_id))
            base_data_store.tiles.tiles.append(tile_ref)
            base_data_store.tiles.tile_size = MAX_TILE_SIZE

            self.add_component_metadata(tile_id, "CalculationEngine", "Tables/Tile-{}")

            tile_idx += 1

        self.objects.update_object_file_store()

    def create_string_table(self):
        table_strings_id, table_strings = self.objects.create_object_from_dict(
            "Index/Tables/DataList-{}",
            {"listType": TSTArchives.TableDataList.ListType.STRING, "nextListID": 1},
            TSTArchives.TableDataList,
        )
        self.add_component_metadata(
            table_strings_id, "CalculationEngine", "Tables/DataList-{}"
        )
        return table_strings_id, table_strings

    def table_height(self, table_id: int) -> int:
        """Return the height of a table in points"""
        table_model = self.objects[table_id]
        bds = self.objects[table_id].base_data_store
        buckets = self.objects[bds.rowHeaders.buckets[0].identifier].headers

        height = 0.0
        for i, row in self.row_storage_map(table_id).items():
            if table_id in self._row_heights and i in self._row_heights[table_id]:
                height += self._row_heights[table_id][i]
            elif row is not None and buckets[i].size != 0.0:
                height += buckets[i].size
            else:
                height += table_model.default_row_height
        return round(height)

    def row_height(self, table_id: int, row_num: int, height: int = None) -> int:
        if height is not None:
            if table_id not in self._row_heights:
                self._row_heights[table_id] = {}
            self._row_heights[table_id][row_num] = height
            return height

        if table_id in self._row_heights and row_num in self._row_heights[table_id]:
            return self._row_heights[table_id][row_num]

        table_model = self.objects[table_id]
        bds = self.objects[table_id].base_data_store
        bucket_id = bds.rowHeaders.buckets[0].identifier
        buckets = self.objects[bucket_id].headers
        bucket_map = {x.index: x for x in buckets}
        if row_num in bucket_map and bucket_map[row_num].size != 0.0:
            return round(bucket_map[row_num].size)
        else:
            return round(table_model.default_row_height)

    def table_width(self, table_id: int) -> int:
        """Return the width of a table in points"""
        table_model = self.objects[table_id]
        bds = self.objects[table_id].base_data_store
        buckets = self.objects[bds.columnHeaders.identifier].headers

        width = 0.0
        for i, col in self.col_storage_map(table_id).items():
            if table_id in self._col_widths and i in self._col_widths[table_id]:
                width += self._col_widths[table_id][i]
            elif col is not None and buckets[i].size != 0.0:
                width += buckets[i].size
            else:
                width += table_model.default_column_width
        return round(width)

    def col_width(self, table_id: int, col_num: int, width: int = None) -> int:
        if width is not None:
            if table_id not in self._col_widths:
                self._col_widths[table_id] = {}
            self._col_widths[table_id][col_num] = width
            return width

        if table_id in self._col_widths and col_num in self._col_widths[table_id]:
            return self._col_widths[table_id][col_num]

        table_model = self.objects[table_id]
        bds = self.objects[table_id].base_data_store
        bucket_id = bds.columnHeaders.identifier
        buckets = self.objects[bucket_id].headers
        bucket_map = {x.index: x for x in buckets}
        if col_num in bucket_map and bucket_map[col_num].size != 0.0:
            return round(bucket_map[col_num].size)
        else:
            return round(table_model.default_column_width)

    def num_header_rows(self, table_id: int, num_headers: int = None) -> int:
        """Return/set the number of header rows"""
        table_model = self.objects[table_id]
        if num_headers is not None:
            table_model.number_of_header_rows = num_headers
        return table_model.number_of_header_rows

    def num_header_cols(self, table_id: int, num_headers: int = None) -> int:
        """Return/set the number of header columns"""
        table_model = self.objects[table_id]
        if num_headers is not None:
            table_model.number_of_header_columns = num_headers
        return table_model.number_of_header_columns

    def table_coordinates(self, table_id: int) -> Tuple[float]:
        table_info = self.objects[self.table_info_id(table_id)]
        return (
            table_info.super.geometry.position.x,
            table_info.super.geometry.position.y,
        )

    def last_table_offset(self, sheet_id):
        """Y offset of the last table in a sheet"""
        if len(self.table_ids(sheet_id)) == 0:
            return 0.0
        table_id = self.table_ids(sheet_id)[-1]
        y_offset = [
            self.objects[self.table_info_id(x)].super.geometry.position.y
            for x in self.table_ids(sheet_id)
            if x == table_id
        ][0]

        return self.table_height(table_id) + y_offset

    def create_drawable(self, sheet_id: int, x: float, y: float) -> object:
        """Create a DrawableArchive for a new table in a sheet"""
        if x is not None:
            table_x = x
        else:
            table_x = 0.0
        if y is not None:
            table_y = y
        elif len(self.objects[sheet_id].drawable_infos) < 1:
            table_y = 0.0
        else:
            table_y = self.last_table_offset(sheet_id) + DEFAULT_TABLE_OFFSET
        drawable = TSDArchives.DrawableArchive(
            parent=TSPMessages.Reference(identifier=sheet_id),
            geometry=TSDArchives.GeometryArchive(
                angle=0.0,
                flags=3,
                position=TSPMessages.Point(x=table_x, y=table_y),
                size=TSPMessages.Size(height=231.0, width=494.0),
            ),
        )
        return drawable

    def add_table(
        self,
        sheet_id: int,
        table_name: str,
        from_table_id: int,
        x: float,
        y: float,
        num_rows: int,
        num_cols: int,
        number_of_header_rows=1,
        number_of_header_columns=1,
    ) -> int:
        from_table = self.objects[from_table_id]

        table_strings_id, table_strings = self.create_string_table()

        # Build a minimal table duplicating references from the source table
        from_table_refs = field_references(from_table)
        table_model_id, table_model = self.objects.create_object_from_dict(
            "CalculationEngine",
            {
                "table_id": str(NumbersUUID()).upper(),
                "number_of_rows": num_rows,
                "number_of_columns": num_cols,
                "table_name": table_name,
                "table_name_enabled": True,
                "default_row_height": DEFAULT_ROW_HEIGHT,
                "default_column_width": DEFAULT_COLUMN_WIDTH,
                "number_of_header_rows": number_of_header_rows,
                "number_of_header_columns": number_of_header_columns,
                "header_rows_frozen": True,
                "header_columns_frozen": True,
                **from_table_refs,
            },
            TSTArchives.TableModelArchive,
        )
        # Supresses Numbers assertions for tables sharing the same data
        table_model.category_owner.identifier = 0

        column_headers_id, column_headers = self.objects.create_object_from_dict(
            "Index/Tables/HeaderStorageBucket-{}",
            {"bucketHashFunction": 1},
            TSTArchives.HeaderStorageBucket,
        )
        self.add_component_metadata(
            column_headers_id, "CalculationEngine", "Tables/HeaderStorageBucket-{}"
        )

        style_table_id, _ = self.objects.create_object_from_dict(
            "Index/Tables/DataList-{}",
            {"listType": TSTArchives.TableDataList.ListType.STYLE, "nextListID": 1},
            TSTArchives.TableDataList,
        )
        self.add_component_metadata(
            style_table_id, "CalculationEngine", "Tables/DataList-{}"
        )

        formula_table_id, _ = self.objects.create_object_from_dict(
            "Index/Tables/TableDataList-{}",
            {"listType": TSTArchives.TableDataList.ListType.FORMULA, "nextListID": 1},
            TSTArchives.TableDataList,
        )
        self.add_component_metadata(
            formula_table_id, "CalculationEngine", "Tables/TableDataList-{}"
        )

        format_table_pre_bnc_id, _ = self.objects.create_object_from_dict(
            "Index/Tables/TableDataList-{}",
            {"listType": TSTArchives.TableDataList.ListType.STYLE, "nextListID": 1},
            TSTArchives.TableDataList,
        )
        self.add_component_metadata(
            format_table_pre_bnc_id,
            "CalculationEngine",
            "Tables/TableDataList-{}",
        )

        data_store_refs = field_references(from_table.base_data_store)
        data_store_refs["stringTable"] = {"identifier": table_strings_id}
        data_store_refs["columnHeaders"] = {"identifier": column_headers_id}
        data_store_refs["styleTable"] = {"identifier": style_table_id}
        data_store_refs["formula_table"] = {"identifier": formula_table_id}
        data_store_refs["format_table_pre_bnc"] = {
            "identifier": format_table_pre_bnc_id
        }
        table_model.base_data_store.MergeFrom(
            TSTArchives.DataStore(
                rowHeaders=TSTArchives.HeaderStorage(bucketHashFunction=1),
                nextRowStripID=1,
                nextColumnStripID=0,
                rowTileTree=TSTArchives.TableRBTree(),
                columnTileTree=TSTArchives.TableRBTree(),
                tiles=TSTArchives.TileStorage(
                    tile_size=DEFAULT_TILE_SIZE, should_use_wide_rows=True
                ),
                **data_store_refs,
            )
        )

        data = [
            [EmptyCell(row_num, col_num) for col_num in range(0, num_cols)]
            for row_num in range(0, num_rows)
        ]

        row_headers_id, _ = self.objects.create_object_from_dict(
            "Index/Tables/HeaderStorageBucket-{}",
            {"bucketHashFunction": 1},
            TSTArchives.HeaderStorageBucket,
        )

        self.add_component_metadata(
            row_headers_id, "CalculationEngine", "Tables/HeaderStorageBucket-{}"
        )
        table_model.base_data_store.rowHeaders.buckets.append(
            TSPMessages.Reference(identifier=row_headers_id)
        )

        self.recalculate_table_data(table_model_id, data)

        table_info_id, table_info = self.objects.create_object_from_dict(
            "CalculationEngine",
            {},
            TSTArchives.TableInfoArchive,
        )
        table_info.tableModel.MergeFrom(
            TSPMessages.Reference(identifier=table_model_id)
        )
        table_info.super.MergeFrom(self.create_drawable(sheet_id, x, y))
        self.add_component_reference(table_info_id, "Document", self.calc_engine_id())

        self.add_formula_owner(
            table_info_id,
            num_rows,
            num_cols,
            number_of_header_rows,
            number_of_header_columns,
        )

        self.objects[sheet_id].drawable_infos.append(
            TSPMessages.Reference(identifier=table_info_id)
        )
        return table_model_id

    def add_formula_owner(
        self,
        table_info_id: int,
        num_rows: int,
        num_cols: int,
        number_of_header_rows: int,
        number_of_header_columns: int,
    ):
        """Create a FormulaOwnerDependenciesArchive that references a TableInfoArchive
        so that cross-references to cells in this table will work."""
        formula_owner_uuid = NumbersUUID()
        calc_engine = self.calc_engine()
        owner_id_map = calc_engine.dependency_tracker.owner_id_map.map_entry
        next_owner_id = max([x.internal_owner_id for x in owner_id_map]) + 1
        formula_deps_id, formula_deps = self.objects.create_object_from_dict(
            "CalculationEngine",
            {
                "formula_owner_uid": formula_owner_uuid.dict2,
                "internal_formula_owner_id": next_owner_id,
                "owner_kind": 1,
                "cell_dependencies": {},
                "range_dependencies": {},
                "volatile_dependencies": {
                    "volatile_time_cells": {},
                    "volatile_random_cells": {},
                    "volatile_locale_cells": {},
                    "volatile_sheet_table_name_cells": {},
                    "volatile_remote_data_cells": {},
                    "volatile_geometry_cell_refs": {},
                },
                "spanning_column_dependencies": {
                    "total_range_for_table": {
                        "top_left_column": 0,
                        "top_left_row": 0,
                        "bottom_right_column": num_cols - 1,
                        "bottom_right_row": num_cols - 1,
                    },
                    "body_range_for_table": {
                        "top_left_column": number_of_header_columns,
                        "top_left_row": number_of_header_rows,
                        "bottom_right_column": num_cols - 1,
                        "bottom_right_row": num_cols - 1,
                    },
                },
                "spanning_row_dependencies": {
                    "total_range_for_table": {
                        "top_left_column": 0,
                        "top_left_row": 0,
                        "bottom_right_column": num_cols - 1,
                        "bottom_right_row": num_cols - 1,
                    },
                    "body_range_for_table": {
                        "top_left_column": number_of_header_columns,
                        "top_left_row": number_of_header_rows,
                        "bottom_right_column": num_cols - 1,
                        "bottom_right_row": num_cols - 1,
                    },
                },
                "whole_owner_dependencies": {"dependent_cells": {}},
                "cell_errors": {},
                "formula_owner": {"identifier": table_info_id},
                "tiled_cell_dependencies": {},
                "uuid_references": {},
                "tiled_range_dependencies": {},
            },
            TSCEArchives.FormulaOwnerDependenciesArchive,
        )
        calc_engine.dependency_tracker.formula_owner_dependencies.append(
            TSPMessages.Reference(identifier=formula_deps_id)
        )
        owner_id_map.append(
            TSCEArchives.OwnerIDMapArchive.OwnerIDMapArchiveEntry(
                internal_owner_id=next_owner_id, owner_id=formula_owner_uuid.protobuf4
            )
        )

    def add_sheet(self, sheet_name: str) -> int:
        """Add a new sheet with a copy of a table from another sheet"""
        sheet_id, _ = self.objects.create_object_from_dict(
            "Document", {"name": sheet_name}, TNArchives.SheetArchive
        )

        self.add_component_reference(
            sheet_id, "CalculationEngine", DOCUMENT_ID, is_weak=True
        )

        self.objects[DOCUMENT_ID].sheets.append(
            TSPMessages.Reference(identifier=sheet_id)
        )

        return sheet_id

    def pack_cell_storage(  # noqa: C901
        self,
        table_id: int,
        data: List,
        row_num: int,
        col_num: int,
        formula_id=None,
        num_format_id=None,
    ) -> bytearray:
        """Create a storage buffer for a cell using v5 (modern) layout"""
        cell = data[row_num][col_num]
        length = 12
        if isinstance(cell, NumberCell):
            flags = 1
            length += 16
            cell_type = TSTArchives.numberCellType
            value = pack_decimal128(cell.value)
        elif isinstance(cell, TextCell):
            flags = 8
            length += 4
            cell_type = TSTArchives.textCellType
            value = pack("<i", self.table_string_key(table_id, cell.value))
        elif isinstance(cell, DateCell):
            flags = 4
            length += 8
            cell_type = TSTArchives.dateCellType
            date_delta = cell.value - EPOCH
            value = pack("<d", float(date_delta.total_seconds()))
        elif isinstance(cell, BoolCell):
            flags = 2
            length += 8
            cell_type = TSTArchives.boolCellType
            value = pack("<d", float(cell.value))
        elif isinstance(cell, DurationCell):
            flags = 2
            length += 8
            cell_type = TSTArchives.durationCellType
            value = value = pack("<d", float(cell.value.total_seconds()))
        elif isinstance(cell, EmptyCell):
            return None
        elif isinstance(cell, MergedCell):
            return None
        else:  # pragma: no cover
            data_type = type(cell).__name__
            table_name = self.table_name(table_id)
            warn(
                f"@{table_name}:[{row_num},{col_num}]: unsupported data type {data_type} for save",
                UnsupportedWarning,
            )
            return None

        storage = bytearray(12)
        storage[0] = 5
        storage[1] = cell_type
        storage += value

        if getattr(cell._storage, "formula_id", None) is not None:
            flags |= 0x200
            length += 4
            storage += pack("<i", cell._storage.formula_id)
        if getattr(cell._storage, "suggest_id", None) is not None:
            flags |= 0x1000
            length += 4
            storage += pack("<i", cell._storage.suggest_id)
        if getattr(cell._storage, "num_format_id", None) is not None:
            flags |= 0x2000
            length += 4
            storage += pack("<i", cell._storage.num_format_id)
            storage[4:6] = pack("<h", 2)
            storage[6:8] = pack("<h", 1)
        if getattr(cell._storage, "text_format_id", None) is not None:
            flags |= 0x20000
            length += 4
            storage += pack("<i", cell._storage.text_format_id)

        storage[8:12] = pack("<i", flags)
        if len(storage) < 32:
            storage += bytearray(32 - length)

        return storage[0:length]

    @lru_cache(maxsize=None)
    def table_formulas(self, table_id: int):
        return TableFormulas(self, table_id)

    @lru_cache(maxsize=None)
    def table_cell_decode(  # noqa: C901
        self, table_id: int, row_num: int, col_num: int
    ) -> Dict:
        buffer = self.storage_buffer(table_id, row_num, col_num)
        if buffer is None:
            return None

        cell = CellStorage(self, table_id, buffer, row_num, col_num)
        return cell

    @lru_cache(maxsize=None)
    def table_bullets(self, table_id: int, string_key: int) -> Dict:
        """
        Extract bullets from a rich text data cell.
        Returns None if the cell is not rich text
        """
        # The table model base data store contains a richTextTable field
        # which is a reference to a TST.TableDataList. The TableDataList
        # has a list of payloads in a field called entries. This will be
        # empty if there is no rich text, i.e. text contents are plaintext.
        #
        # "entries": [
        #     { "key": 1,
        #       "refcount": 1,
        #       "richTextPayload": { "identifier": "2035264" }
        #     },
        #     ...
        #
        # entries[n].richTextPayload.identifier is a reference to a
        # TST.RichTextPayloadArchive that contains a field called storage
        # that itself is a reference to a TSWP.StorageArchive that contains
        # the actual paragraph data:
        #
        # "tableParaStyle": {
        #     "entries": [
        #         { "characterIndex": 0, "object": { "identifier": "1566948" } },
        #         { "characterIndex": 6 },
        #         { "characterIndex": 12 }
        #     ]
        # },
        # "text": [ "Lorem\nipsum\ndolor" ]
        #
        # The bullet character is stored in a TSWP.ListStyleArchive. Each bullet
        # paragraph can have its own reference to a list style or, if none is
        # defined, the previous bullet character is used. All StorageArchives
        # reference a ListStyleArchive but not all those ListStyleArchives have
        # a string with a new bullet character
        bds = self.objects[table_id].base_data_store
        rich_text_table = self.objects[bds.rich_text_table.identifier]
        for entry in rich_text_table.entries:
            if string_key == entry.key:
                payload = self.objects[entry.rich_text_payload.identifier]
                payload_storage = self.objects[payload.storage.identifier]
                payload_entries = payload_storage.table_para_style.entries
                table_list_styles = payload_storage.table_list_style.entries
                offsets = [e.character_index for e in payload_entries]

                cell_text = payload_storage.text[0]
                bullets = []
                bullet_chars = []
                for i, offset in enumerate(offsets):
                    if i == len(offsets) - 1:
                        bullets.append(cell_text[offset:])
                    else:
                        # Remove the last character (always newline)
                        bullets.append(cell_text[offset : offsets[i + 1] - 1])

                    # Re-use last style if there is none defined for this bullet
                    if i < len(table_list_styles):
                        table_list_style = table_list_styles[i]

                    bullet_style = self.objects[table_list_style.object.identifier]
                    if len(bullet_style.strings) > 0:
                        bullet_char = bullet_style.strings[0]
                    elif len(bullet_style.number_types) > 0:
                        number_type = bullet_style.number_types[0]
                        bullet_char = formatted_number(number_type, i)
                    else:
                        bullet_char = ""

                    bullet_chars.append(bullet_char)

                return {
                    "text": cell_text,
                    "bullets": bullets,
                    "bullet_chars": bullet_chars,
                }
        return None


def cell_reference_node(row_num: int, col_num: int, formula_id: int, base_owner_uid):
    node = TSCEArchives.ASTNodeArrayArchive.ASTNodeArchive(
        AST_node_type=TSCEArchives.ASTNodeArrayArchive.ASTNodeType.CELL_REFERENCE_NODE,
        AST_column=TSCEArchives.ASTNodeArrayArchive.ASTColumnCoordinateArchive(
            column=col_num, absolute=True
        ),
        AST_row=TSCEArchives.ASTNodeArrayArchive.ASTRowCoordinateArchive(
            row=row_num, absolute=True
        ),
        AST_cross_table_reference_extra_info=(
            TSCEArchives.ASTNodeArrayArchive.ASTCrossTableReferenceExtraInfoArchive(
                table_id=base_owner_uid.protobuf4
            )
        ),
    )
    return node


def formatted_number(number_type, index):
    """Returns the numbered index bullet formatted for different types"""
    bullet_char = BULLET_PREFIXES[number_type]
    bullet_char += BULLET_CONVERTION[number_type](index)
    bullet_char += BULLET_SUFFIXES[number_type]

    return bullet_char


def node_to_col_ref(node: object, table_name: str, col_num: int) -> str:
    if node.AST_column.absolute:
        col = node.AST_column.column
    else:
        col = col_num + node.AST_column.column

    col_name = xl_col_to_name(col, node.AST_column.absolute)
    if table_name is not None:
        return f"{table_name}::{col_name}"
    else:
        return col_name


def node_to_row_col_ref(
    node: object, table_name: str, row_num: int, col_num: int
) -> str:
    if node.AST_row.absolute:
        row = node.AST_row.row
    else:
        row = row_num + node.AST_row.row
    if node.AST_column.absolute:
        col = node.AST_column.column
    else:
        col = col_num + node.AST_column.column

    ref = xl_rowcol_to_cell(
        row,
        col,
        row_abs=node.AST_row.absolute,
        col_abs=node.AST_column.absolute,
    )
    if table_name is not None:
        return f"{table_name}::{ref}"
    else:
        return ref


def get_storage_buffers_for_row(
    storage_buffer: bytes, offsets: list, num_cols: int, has_wide_offsets: bool
) -> List[bytes]:
    """
    Extract storage buffers for each cell in a table row

    Args:
        storage_buffer:  cell_storage_buffer or cell_storage_buffer for a table row
        offsets: 16-bit cell offsets for a table row
        num_cols: number of columns in a table row
        has_wide_offsets: use 4-byte offsets rather than 1-byte offset

    Returns:
         data: list of bytes for each cell in a row, or None if empty
    """
    offsets = array("h", offsets).tolist()
    if has_wide_offsets:
        offsets = [o * 4 for o in offsets]

    data = []
    for col_num in range(num_cols):
        if col_num >= len(offsets):
            break

        start = offsets[col_num]
        if start < 0:
            data.append(None)
            continue

        if col_num == (len(offsets) - 1):
            end = len(storage_buffer)
        else:
            end = None
            # Find next positive offset
            for i, x in enumerate(offsets[col_num + 1 :]):
                if x >= 0:
                    end = offsets[col_num + i + 1]
                    break
            if end is None:
                end = len(storage_buffer)
        data.append(storage_buffer[start:end])

    return data


def clear_field_container(obj):
    """Remove all entries from a protobuf RepeatedCompositeFieldContainer
    in a portable fashion"""
    if hasattr(obj, "clear"):
        obj.clear()
    else:
        while len(obj) > 0:
            _ = obj.pop()


def pack_decimal128(value: float) -> bytearray:
    buffer = bytearray(16)
    exp = math.floor(math.log10(math.e) * math.log(abs(value))) if value != 0.0 else 0
    exp = int(exp) + 0x1820 - 16
    mantissa = int(value / math.pow(10, exp - 0x1820))
    buffer[15] |= exp >> 7
    buffer[14] |= (exp & 0x7F) << 1
    i = 0
    while mantissa >= 1:
        buffer[i] = mantissa & 0xFF
        i += 1
        mantissa = int(mantissa / 256)
    if value < 0:
        buffer[15] |= 0x80
    return buffer


def field_references(obj: object) -> dict:
    """Return a dict of all fields in an object that are references to other objects"""
    refs = {
        x[0].name: {"identifier": getattr(obj, x[0].name).identifier}
        for x in obj.ListFields()
        if type(getattr(obj, x[0].name)) == TSPMessages.Reference
    }
    return refs
