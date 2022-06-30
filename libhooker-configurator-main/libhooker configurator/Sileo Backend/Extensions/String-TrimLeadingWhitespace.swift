//
//  String-TrimLeadingWhitespace.swift
//  Sileo
//
//  Created by CoolStar on 6/23/19.
//  Copyright © 2019 CoolStar. All rights reserved.
//

import Foundation

extension String {
    func trimmingLeadingWhitespace() -> String {
        self.replacingOccurrences(of: "^\\s+", with: "", options: .regularExpression)
    }
}
