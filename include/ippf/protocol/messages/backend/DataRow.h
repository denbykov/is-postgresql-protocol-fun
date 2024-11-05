#pragma once

#include <ippf/core/buffer.h>
#include <ippf/core/buffer_op.h>
#include <ippf/core/to_x_endian.h>

#include <cstdint>
#include <memory>

namespace ippf::protocol::messages::backend {
    class DataRow {
    public:
        DataRow(core::buffer&& buf) : buf_(std::move(buf)) {}

        DataRow(const DataRow& other) = delete;
        DataRow(DataRow&&) = default;

        DataRow operator==(const DataRow& other) = delete;
        DataRow& operator=(DataRow&&) = default;

        const core::buffer* data() const { return &buf_; }

    private:
        core::buffer buf_;
    };
}  // namespace ippf::protocol::messages::backend